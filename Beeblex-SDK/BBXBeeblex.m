//
//  BBXBeeblex.m
//  beeblex
//
//  Created by Marco Tabini on 2012-07-16.
//  Copyright (c) 2012 Blue Parabola, LLC. All rights reserved.
//

#import "BBXBeeblex.h"

#import "BBXBeeblex_Private.h"
#import "_BBXBase64.h"

#import <Security/Security.h>


const struct BBXBeeblexExceptionNames BBXBeeblexExceptionNames = {
    .configurationTransactionException = @"BBXConfigurationTransactionException"
};

const struct BBXBeeblexErrorCodes BBXBeeblexErrorCodes = {
    .serverError = -1000,
    
    .iapValidationError = -2000
};


@interface BBXBeeblex()

@property (nonatomic) NSString *apiKey;
@property (nonatomic) SecKeyRef publicKey;

@end


@implementation BBXBeeblex

@synthesize apiKey = _apiKey;
@synthesize publicKey = _publicKey;

@synthesize _useSSL = __useSSL;


#pragma mark - RSA key manipulation


- (SecKeyRef) publicKeyFromBase64PEMString:(NSString *) publicKeyPEM {
    // Remove fences
    
    publicKeyPEM = [publicKeyPEM substringFromIndex:[publicKeyPEM rangeOfString:@"\n"].location + 1];
    publicKeyPEM = [publicKeyPEM substringToIndex:[publicKeyPEM rangeOfString:@"\n" options:NSBackwardsSearch].location];
    
    NSData *rawFormattedKey = [_BBXBase64 dataFromBase64String:publicKeyPEM];
    NSString *refString = @"BeeblexPublicKey";
        
    /* Now strip the uncessary ASN encoding guff at the start */
    unsigned char * bytes = (unsigned char *)[rawFormattedKey bytes];
    size_t bytesLen = [rawFormattedKey length];
    
    /* Strip the initial stuff */
    size_t i = 0;
    if (bytes[i++] != 0x30)
        return Nil;
    
    /* Skip size bytes */
    if (bytes[i] > 0x80)
        i += bytes[i] - 0x80 + 1;
    else
        i++;
    
    if (i >= bytesLen)
        return Nil;
    
    if (bytes[i] != 0x30)
        return Nil;
    
    /* Skip OID */
    i += 15;
    
    if (i >= bytesLen - 2)
        return Nil;
    
    if (bytes[i++] != 0x03)
        return Nil;
    
    /* Skip length and null */
    if (bytes[i] > 0x80)
        i += bytes[i] - 0x80 + 1;
    else
        i++;
    
    if (i >= bytesLen)
        return Nil;
    
    if (bytes[i++] != 0x00)
        return Nil;
    
    if (i >= bytesLen)
        return Nil;
    
    /* Here we go! */
    NSData * extractedKey = [NSData dataWithBytes:&bytes[i] length:bytesLen - i];
    
    /* Load as a key ref */
    OSStatus error = noErr;
    CFTypeRef persistPeer = NULL;
    
    NSData * refTag = [refString dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableDictionary * keyAttr = [[NSMutableDictionary alloc] init];
    
    [keyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [keyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyAttr setObject:refTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    /* First we delete any current keys */
    SecItemDelete((__bridge CFDictionaryRef) keyAttr);
    
    [keyAttr setObject:extractedKey forKey:(__bridge id)kSecValueData];
    [keyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    error = SecItemAdd((__bridge CFDictionaryRef) keyAttr, (CFTypeRef *)&persistPeer);
    
    if (persistPeer == nil || ( error != noErr && error != errSecDuplicateItem)) {
        NSLog(@"Problem adding public key to keychain");
        return Nil;
    }
    
    CFRelease(persistPeer);
    
    SecKeyRef publicKeyRef = nil;
    
    /* Now we extract the real ref */
    [keyAttr removeAllObjects];
    /*
     [keyAttr setObject:(id)persistPeer forKey:(id)kSecValuePersistentRef];
     [keyAttr setObject:[NSNumber numberWithBool:YES] forKey:(id)kSecReturnRef];
     */
    [keyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [keyAttr setObject:refTag forKey:(__bridge id)kSecAttrApplicationTag];
    [keyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    // Get the persistent key reference.
    error = SecItemCopyMatching((__bridge CFDictionaryRef)keyAttr, (CFTypeRef *)&publicKeyRef);
    
    if (publicKeyRef == nil || ( error != noErr && error != errSecDuplicateItem)) {
        NSLog(@"Error retrieving public key reference from chain");
        return Nil;
    }
    
    return publicKeyRef;
}


#pragma mark - API Key Manipulation


- (BOOL) setAPIKey:(NSString *) apiKey {
    NSData *data = [_BBXBase64 dataFromBase64String:apiKey];

    NSString *str = [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];
    
    if (!str.length) {
        @throw [NSException exceptionWithName:BBXBeeblexExceptionNames.configurationTransactionException
                                       reason:NSLocalizedString(@"Invalid API Key. Please check your key and try again.", Nil)
                                     userInfo:Nil];
    }
    
    NSArray *components = [str componentsSeparatedByString:@","];
    
    if (components.count != 2) {
        @throw [NSException exceptionWithName:BBXBeeblexExceptionNames.configurationTransactionException
                                       reason:NSLocalizedString(@"Invalid API Key. Please check your key and try again.", Nil)
                                     userInfo:Nil];
    }
    
    self.apiKey = [components objectAtIndex:0];
    
    self.publicKey = [self publicKeyFromBase64PEMString:[components objectAtIndex:1]];
    
    if (self.apiKey.length != 128) {
        @throw [NSException exceptionWithName:BBXBeeblexExceptionNames.configurationTransactionException
                                       reason:NSLocalizedString(@"Invalid API Key. Please check your key and try again.", Nil)
                                     userInfo:Nil];
    }

    return YES;
}


#pragma mark - URLs


+ (NSString *) _baseURL {
//    return @"http://beeblex.local/api/v1";
    return @"http://www.beeblex.com/api/v1";
}


+ (NSString *) _baseSecureURL {
//    return @"http://beeblex.local/api/v1";
    return @"https://www.beeblex.com/api/v1";
}


- (NSString *) _currentBaseURL {
    return self._useSSL ? [self.class _baseSecureURL] : [self.class _baseURL];
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
    return @"1.0 beta 2 (Samba)";
}


+ (void) setUseSSL:(BOOL)useSSL {
    [self _globalInstance]._useSSL = YES;
}


@end
