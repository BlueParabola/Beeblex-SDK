//
//  BBXBeeblex.m
//  beeblex
//
//  Created by Marco Tabini on 2012-07-16.
//  Copyright (c) 2012 Blue Parabola, LLC. All rights reserved.
//

#import "BBXBeeblex.h"

#import "BBXBeeblex_Private.h"
#import "_BBXCrypto.h"


const struct BBXBeeblexExceptionNames BBXBeeblexExceptionNames = {
    .invalidApiKey = @"BBXInvalidAPIKeyException",
    .invalidSKPaymentTransaction = @"invalidSKPaymentTransaction",
    
    .cannotRecycleVerificationRequest = @"BBXCannotRecycleVerificationRequest"
};


@interface BBXBeeblex()

@property (nonatomic) NSString *apiKey;
@property (nonatomic) NSString *publicKey;

@end


@implementation BBXBeeblex

@synthesize apiKey = _apiKey;
@synthesize publicKey = _publicKey;


#pragma mark - API Key Manipulation


- (BOOL) setAPIKey:(NSString *) apiKey {
    NSData *data = [apiKey dataUsingEncoding:NSASCIIStringEncoding];
    data = [_BBXCrypto decodeBase64:data WithNewLines:NO];

    NSString *str = [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];
    
    if (!str.length) {
        @throw [NSException exceptionWithName:BBXBeeblexExceptionNames.invalidApiKey
                                       reason:NSLocalizedString(@"Invalid API Key. Please check your key and try again.", Nil)
                                     userInfo:Nil];
    }
    
    NSArray *components = [str componentsSeparatedByString:@","];
    
    if (components.count != 2) {
        @throw [NSException exceptionWithName:BBXBeeblexExceptionNames.invalidApiKey
                                       reason:NSLocalizedString(@"Invalid API Key. Please check your key and try again.", Nil)
                                     userInfo:Nil];
    }
    
    self.apiKey = [components objectAtIndex:0];
    self.publicKey = [components objectAtIndex:1];
    
    if (self.apiKey.length != 128) {
        @throw [NSException exceptionWithName:BBXBeeblexExceptionNames.invalidApiKey
                                       reason:NSLocalizedString(@"Invalid API Key. Please check your key and try again.", Nil)
                                     userInfo:Nil];
    }
    
    return YES;
}


#pragma mark - Initialization


+ (BOOL) initializeWithAPIKey:(NSString *)apiKey {
    return [[self _globalInstance] setAPIKey:apiKey];
}


+ (BBXBeeblex *) _globalInstance {
    static BBXBeeblex *globalInstance;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        globalInstance = [[BBXBeeblex alloc] init];
    });
    
    return globalInstance;
}


+ (NSString *) versionNumber {
    return @"1.0 (Samba)";
}


+ (NSString *) _baseURL {
//    return @"http://beeblex.local/api/v1";
    return @"http://www.beeblex.com/api/v1";
}


+ (NSString *) _baseSecureURL {
//    return @"http://beeblex.local/api/v1";
    return @"https://www.beeblex.com/api/v1";
}


@end
