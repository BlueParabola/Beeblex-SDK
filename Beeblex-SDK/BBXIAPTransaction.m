//
//  BBXIAPTransaction.m
//  beeblex
//
//  Created by Marco Tabini on 2012-07-16.
//  Copyright (c) 2012 Blue Parabola, LLC. All rights reserved.
//

#import "BBXBeeblex.h"
#import "BBXBeeblex_Private.h"

#import "BBXIAPTransaction.h"

#import "_BBXEncryptedTransaction.h"
#import "_BBXCrypto.h"
#import "_BBXReachability.h"


const struct BBXIAPTransactionErrorCodes BBXIAPTransactionErrorCodes = {
    .domain = @"BBXIAPTransactionDomain"
};


@interface BBXIAPTransaction()


@property (nonatomic) BOOL running;
@property (nonatomic) BOOL hasRun;

@property (nonatomic) BOOL hasConfigurationError;
@property (nonatomic) BOOL hasServerError;
@property (nonatomic) BOOL hasClientError;

@property (nonatomic) BOOL validationExpired;
@property (nonatomic) BOOL transactionVerified;
@property (nonatomic) BOOL transactionIsDuplicate;

@property (nonatomic) NSDictionary *validatedTransactionData;


@end


@implementation BBXIAPTransaction {
    SKPaymentTransaction *_transaction;
}

@synthesize useSandbox = _useSandbox;

@synthesize useSecureConnection = _useSecureConnection;

@synthesize running = _running;
@synthesize hasRun = _hasRun;

@synthesize hasServerError = _hasServerError;
@synthesize hasClientError = _hasClientError;

@synthesize validationExpired = _validationExpired;
@synthesize transactionVerified = _transactionVerified;
@synthesize transactionIsDuplicate = _transactionIsDuplicate;

@synthesize validatedTransactionData = _validatedTransactionData;


#pragma mark - Properties


- (void) setUseSecureConnection:(BOOL)useSecureConnection {
    NSLog(@"Warning: @useSecureConnection is deprecated and will be removed from future versions of the SDK. Use +[BBXBeeblex setUseSSL:] instead.");
    [BBXBeeblex setUseSSL:useSecureConnection];
}


- (BOOL) useSecureConnection {
    return [BBXBeeblex _globalInstance]._useSSL;
}


- (BOOL) hasClientError {
    NSLog(@"Warning: @hasClientError is deprecated and will be removed from future versions of the SDK. Use @hasServerError instead.");
    return self.hasServerError;
}


#pragma mark - Validation


- (void) validateWithCompletionBlock:(BBXAPITransactionCompletionBlock)completionBlock {
    if (self.hasRun) {
        @throw [NSException exceptionWithName:BBXBeeblexExceptionNames.configurationTransactionException
                                       reason:NSLocalizedString(@"BBXAPITransaction objects cannot be reused.", Nil)
                                     userInfo:Nil];
    }
    
    self.hasRun = YES;
    self.running = YES;
    
    NSData *symmetricKey = [_BBXCrypto getKeyDataWithLength:8];
    
    NSAssert1(symmetricKey.length == 8, @"The secret key should be 8 bytes; %d found instead", symmetricKey.length);
    
    NSDictionary *payload = @{
        @"transactionData"  : [[NSString alloc] initWithData:_transaction.transactionReceipt
                                                    encoding:NSUTF8StringEncoding],
        @"submissionDate"   : @((NSUInteger) [[NSDate date] timeIntervalSince1970]),
        @"transactionId"    : _transaction.transactionIdentifier,
        @"useSandbox"       : @(self.useSandbox)
    };
    
    NSData *jsonPayload = [NSJSONSerialization dataWithJSONObject:payload
                                                          options:0
                                                            error:Nil];
    
    [_BBXEncryptedTransaction
     processTransactionWithPayload:jsonPayload
     errorDomain:BBXIAPTransactionErrorCodes.domain
     callback:^(id response, NSError *error) {
         if (error) {
             self.hasServerError = YES;
             self.running = NO;
             
             completionBlock(error);
             return;
         }
         
         NSDictionary *dictionary = (NSDictionary *) response;
         
         if (!dictionary || ![dictionary isKindOfClass:[NSDictionary class]]) {
             error = [NSError errorWithDomain:BBXIAPTransactionErrorCodes.domain
                                         code:BBXBeeblexErrorCodes.serverError
                                     userInfo:@{
                   NSLocalizedDescriptionKey : NSLocalizedString(@"The validation data returned by the server was of the wrong type.", Nil)}];
             
             self.hasServerError = YES;
             self.running = NO;
             completionBlock(error);
             return;
         }

         NSDate *expirationDate = [NSDate dateWithTimeIntervalSince1970:[[dictionary objectForKey:@"expires"] floatValue]];
         
         if ([[NSDate date] earlierDate:expirationDate] == expirationDate) {
             error = [NSError errorWithDomain:BBXIAPTransactionErrorCodes.domain
                                         code:BBXBeeblexErrorCodes.iapValidationError
                                     userInfo:@{
                   NSLocalizedDescriptionKey : NSLocalizedString(@"The validation data returned by the server has expired.", Nil)}];
         
             self.running = NO;
             completionBlock(error);
         }
         
         NSDictionary *iapData = [dictionary objectForKey:@"iapData"];
         
         if (![[iapData objectForKey:@"status"] integerValue]) {
             self.transactionVerified = YES;
             self.validatedTransactionData = iapData;
             self.transactionIsDuplicate = [[dictionary objectForKey:@"duplicate"] boolValue];
         }
         
         completionBlock(Nil);
         
     }];

}


#pragma mark - Initialization


- (id) initWithTransaction:(SKPaymentTransaction *) transaction {
    self = [super init];
    
    if (self) {
        if (transaction.transactionState != SKPaymentTransactionStatePurchased && transaction.transactionState != SKPaymentTransactionStateRestored) {
            @throw [NSException exceptionWithName:BBXBeeblexExceptionNames.configurationTransactionException
                                           reason:@"This transaction is not in a purchased or restored state"
                                         userInfo:Nil];
        }
        
        _transaction = transaction;
    }
    
    return self;
}


+ (BOOL) canValidateTransactions {
    return [_BBXReachability reachabilityForInternetConnection].isReachable;
}


@end
