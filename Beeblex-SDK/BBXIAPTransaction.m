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

#import "_BBXCrypto.h"
#import "_BBXReachability.h"


const struct BBXIAPTransactionErrorCodes BBXIAPTransactionErrorCodes = {
    .domain = @"BBXIAPTransactionDomain",
    
    .success = 0,

    // Initialization Errors
    
    .initializationErrors = 1000,
    .encryptionEngineCannotBeInitialized = 1000,
    
    // Remote Errors
    
    .remoteErrors = 2000,
    
    .cannotContactBBXValidationServer = 2000,
    .cannotDecryptServerData = 2001,
    .clientError = 2002,
    .serverError = 2003

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


#pragma mark - Validation


- (void) validateWithCompletionBlock:(BBXAPITransactionCompletionBlock)completionBlock {
    if (self.hasRun) {
        self.hasConfigurationError = YES;
        @throw [NSException exceptionWithName:BBXBeeblexExceptionNames.cannotRecycleVerificationRequest
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

    _BBXCrypto *crypto = [[_BBXCrypto alloc] initWithSymmetricKey:symmetricKey];
    
    if (!crypto) {
        self.hasConfigurationError = YES;
        NSError *error = [[NSError alloc] initWithDomain:BBXIAPTransactionErrorCodes.domain
                                                    code:BBXIAPTransactionErrorCodes.encryptionEngineCannotBeInitialized
                                                userInfo:@{ NSLocalizedDescriptionKey :  NSLocalizedString(@"The encryption engine cannot be initialized.", Nil)}];
        
        self.running = NO;
        completionBlock(error);
        return;
    }
    
    [crypto setClearTextWithData:[NSJSONSerialization dataWithJSONObject:payload
                                                                          options:0
                                                                            error:Nil]];
    NSData *cypherText = [crypto encrypt:@"blowfish"];
    
    if (!cypherText) {
        self.hasConfigurationError = YES;
        NSError *error = [[NSError alloc] initWithDomain:BBXIAPTransactionErrorCodes.domain
                                                    code:BBXIAPTransactionErrorCodes.encryptionEngineCannotBeInitialized
                                                userInfo:@{ NSLocalizedDescriptionKey :  NSLocalizedString(@"Cannot generate encryption key.", Nil)}];
        
        self.running = NO;
        completionBlock(error);
        return;
    }

    
    crypto = [[_BBXCrypto alloc] initWithPublicKey:[[BBXBeeblex _globalInstance].publicKey dataUsingEncoding:NSASCIIStringEncoding]];
    
    if (!crypto) {
        self.hasConfigurationError = YES;
        NSError *error = [[NSError alloc] initWithDomain:BBXIAPTransactionErrorCodes.domain
                                                    code:BBXIAPTransactionErrorCodes.encryptionEngineCannotBeInitialized
                                                userInfo:@{ NSLocalizedDescriptionKey :  NSLocalizedString(@"Cannot generate public key.", Nil)}];
        
        self.running = NO;
        completionBlock(error);
        return;
    }
    
    [crypto setClearTextWithData:symmetricKey];
    
    NSData *signature = [crypto signPublic];

    if (!signature) {
        self.hasConfigurationError = YES;
        NSError *error = [[NSError alloc] initWithDomain:BBXIAPTransactionErrorCodes.domain
                                                    code:BBXIAPTransactionErrorCodes.encryptionEngineCannotBeInitialized
                                                userInfo:@{ NSLocalizedDescriptionKey :  NSLocalizedString(@"Cannot encrypt symmetric key.", Nil)}];
        
        self.running = NO;
        completionBlock(error);
        return;
    }
    
    NSDictionary *finalPayload = @{
        @"signature" : [_BBXCrypto encodeBase64:signature WithNewlines:NO],
        @"payload" : [_BBXCrypto encodeBase64:cypherText WithNewlines:NO]
    };
    
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:finalPayload
                                                       options:0
                                                         error:Nil];
    
    NSAssert(jsonData, @"Unable to create JSON payload");
    
    if (!self.useSecureConnection) {
        NSLog(@"Warning: Beeblex is not using HTTPS to connect to the server, most likely due to export compliance reasons. This is not necessarily a problem, but we thought you should know.");
    }
    
    NSURL *URL = [NSURL URLWithString:[NSString stringWithFormat:@"%@/app/%@/verify",
                                       self.useSecureConnection ? [BBXBeeblex _baseSecureURL] : [BBXBeeblex _baseURL],
                                       [BBXBeeblex _globalInstance].apiKey]];
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:URL];
    request.HTTPMethod = @"POST";
    request.HTTPBody = jsonData;
    
    [NSURLConnection sendAsynchronousRequest:request
                                       queue:[NSOperationQueue mainQueue]
                           completionHandler:^(NSURLResponse *response, NSData *data, NSError *error) {
                               if (!data || error) {
                                   error = [NSError errorWithDomain:BBXIAPTransactionErrorCodes.domain
                                                               code:BBXIAPTransactionErrorCodes.cannotContactBBXValidationServer
                                                           userInfo:@{
                                         NSLocalizedDescriptionKey : NSLocalizedString(@"Unable to contact the Beeblex validation server.", Nil)}];

                                   self.hasServerError = YES;
                                   self.running = NO;
                                   completionBlock(error);
                                   return;
                               }
                               
                               NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *) response;

                               if (httpResponse.statusCode > 399 && httpResponse.statusCode < 500) {
                                   error = [NSError errorWithDomain:BBXIAPTransactionErrorCodes.domain
                                                               code:BBXIAPTransactionErrorCodes.clientError
                                                           userInfo:@{
                                         NSLocalizedDescriptionKey : [NSHTTPURLResponse localizedStringForStatusCode:httpResponse.statusCode]}];
                                   
                                   self.hasClientError = YES;
                                   self.running = NO;
                                   completionBlock(error);
                                   return;
                               }
                               
                               if (httpResponse.statusCode > 499 && httpResponse.statusCode < 600) {
                                   error = [NSError errorWithDomain:BBXIAPTransactionErrorCodes.domain
                                                               code:BBXIAPTransactionErrorCodes.serverError
                                                           userInfo:@{
                                         NSLocalizedDescriptionKey : [NSHTTPURLResponse localizedStringForStatusCode:httpResponse.statusCode]}];
                                   
                                   self.hasServerError = YES;
                                   self.running = NO;
                                   completionBlock(error);
                                   return;
                               }
                               
                               data = [_BBXCrypto decodeBase64:data WithNewLines:NO];
                               
                               if (!data.length) {
                                   error = [NSError errorWithDomain:BBXIAPTransactionErrorCodes.domain
                                                               code:BBXIAPTransactionErrorCodes.cannotDecryptServerData
                                                           userInfo:@{
                                         NSLocalizedDescriptionKey : NSLocalizedString(@"Unable to decrypt the validation data.", Nil)}];
                                   
                                   self.hasServerError = YES;
                                   self.running = NO;
                                   completionBlock(error);
                                   return;
                               }
                               
                               _BBXCrypto *crypto = [[_BBXCrypto alloc] initWithSymmetricKey:symmetricKey];
                               
                               if (!crypto) {
                                   self.hasConfigurationError = YES;
                                   NSError *error = [[NSError alloc] initWithDomain:BBXIAPTransactionErrorCodes.domain
                                                                               code:BBXIAPTransactionErrorCodes.encryptionEngineCannotBeInitialized
                                                                           userInfo:@{ NSLocalizedDescriptionKey :  NSLocalizedString(@"The encryption engine cannot be initialized.", Nil)}];
                                   
                                   self.running = NO;
                                   completionBlock(error);
                                   return;
                               }

                               [crypto setCipherText:data];
                               
                               NSData *result = [crypto decrypt:@"blowfish"];
                               
                               if (!result) {
                                   error = [NSError errorWithDomain:BBXIAPTransactionErrorCodes.domain
                                                               code:BBXIAPTransactionErrorCodes.cannotDecryptServerData
                                                           userInfo:@{
                                         NSLocalizedDescriptionKey : NSLocalizedString(@"Unable to decrypt the validation data.", Nil)}];
                                   
                                   self.hasServerError = YES;
                                   self.running = NO;
                                   completionBlock(error);
                                   return;
                               }

                               NSDictionary *dictionary = [NSJSONSerialization JSONObjectWithData:result
                                                                                          options:0
                                                                                            error:&error];
                               
                               if (!dictionary || ![dictionary isKindOfClass:[NSDictionary class]]) {
                                   error = [NSError errorWithDomain:BBXIAPTransactionErrorCodes.domain
                                                               code:BBXIAPTransactionErrorCodes.cannotDecryptServerData
                                                           userInfo:@{
                                         NSLocalizedDescriptionKey : NSLocalizedString(@"Unable to decrypt the validation data.", Nil)}];
                                   
                                   self.hasServerError = YES;
                                   self.running = NO;
                                   completionBlock(error);
                                   return;
                               }
                               
                               NSDate *expirationDate = [NSDate dateWithTimeIntervalSince1970:[[dictionary objectForKey:@"expires"] floatValue]];
                               
                               if ([[NSDate date] earlierDate:expirationDate] == expirationDate) {
                                   self.validationExpired = YES;
                                   self.running = NO;
                                   completionBlock(Nil);
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
            @throw [NSException exceptionWithName:BBXBeeblexExceptionNames.invalidSKPaymentTransaction
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
