//
//  _BBXEncryptedTransaction.m
//  Beeblex-SDK
//
//  Created by Marco Tabini on 2012-07-19.
//  Copyright (c) 2012 Blue Parabola, LLC. All rights reserved.
//

#import "_BBXEncryptedTransaction.h"

#import "BBXBeeblex.h"
#import "BBXBeeblex_Private.h"
#import "_BBXBase64.h"

#import "JSONKit/_BBXJSONKit.h"

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>


@implementation _BBXEncryptedTransaction


+ (NSData *) _getKeyDataWithLength:(NSInteger) length {
    uint8_t *bytes;
    
    bytes = malloc(length);
    
    if (!bytes) {
        return Nil;
    }
    
    if (SecRandomCopyBytes(kSecRandomDefault,
                             length,
                             bytes)) {
        free(bytes);
        return Nil;
    }
    
    NSData *result = [NSData dataWithBytes:bytes length:length];
    
    free(bytes);
    
    return result;
}


+ (NSData *) _processedDataFromData:(NSData *) data withSymmetricKey:(NSData *) signature encrypt:(BOOL) encrypt {
    unsigned char symmetricKey[16];
    unsigned char iv[16];
    
    CC_MD5(signature.bytes, signature.length, symmetricKey);
    
    NSMutableData *hash = [NSMutableData dataWithBytes:symmetricKey length:16];
    [hash appendData:signature];
    
    CC_MD5(hash.bytes, hash.length, iv);
    
    unsigned long outputLength = 0;
    unsigned char *outputData = malloc(data.length + 8);
    
    NSAssert(outputData, @"Memory allocation error.");
    
    if (CCCrypt(encrypt ? kCCEncrypt : kCCDecrypt,
                kCCAlgorithmBlowfish,
                ccPKCS7Padding,
                &symmetricKey,
                16,
                &iv,
                data.bytes,
                data.length,
                outputData,
                data.length + 8,
                &outputLength) != kCCSuccess) {
        
        free(outputData);
        return Nil;
        
    }
    
    NSData *result = [NSData dataWithBytes:outputData length:outputLength];
    
    free(outputData);
    
    return result;
}


+ (void) processTransactionWithPayload:(NSData *)payload errorDomain:(NSString *)errorDomain callback:(BBXEncryptedTransactionResultBlock)completionBlock {
    BBXBeeblex *beeblex = [BBXBeeblex _globalInstance];
    
    void(^errorBlock)(NSString *errorString) = ^(NSString *errorString) {
        NSError *error = [[NSError alloc] initWithDomain:errorDomain
                                                    code:BBXBeeblexErrorCodes.serverError
                                                userInfo:[NSDictionary dictionaryWithObject:errorString
                                                                                     forKey:NSLocalizedDescriptionKey]];
        completionBlock(Nil, error);
    };
        
    NSData *symmetricKey = [self.class _getKeyDataWithLength:8];
    
    NSAssert1(symmetricKey.length == 8, @"The secret key should be 8 bytes; %d found instead", symmetricKey.length);
    
    NSData *cypherText = [self _processedDataFromData:payload withSymmetricKey:symmetricKey encrypt:YES];
    
    if (!cypherText) {
        errorBlock(NSLocalizedString(@"Cannot encrypt main payload using a symmetric algorithm.", Nil));
        return;
    }

    unsigned char *encryptedData = malloc(1024);
    
    NSAssert(encryptedData, @"Memory allocation error.");

    unsigned long length = 1024; // Ought to be more than enough
    
    OSStatus error = SecKeyEncrypt(beeblex.publicKey,
                                   kSecPaddingPKCS1,
                                   symmetricKey.bytes,
                                   symmetricKey.length,
                                   encryptedData,
                                   &length);
    
    if (error) {
        free(encryptedData);
        errorBlock([NSString stringWithFormat:NSLocalizedString(@"Unable to sign transaction: OSStatus error %ld.", Nil), error]);
        return;
    }

    NSData *signature = [NSData dataWithBytes:encryptedData length:length];
    
    free(encryptedData);
    
    if (!signature) {
        errorBlock(NSLocalizedString(@"Cannot encrypt symmetric key.", Nil));
        return;
    }
    
    NSDictionary *finalPayload = [NSDictionary dictionaryWithObjectsAndKeys:
                                  [_BBXBase64 base64EncodedStringFromData:signature], @"signature",
                                  [_BBXBase64 base64EncodedStringFromData:cypherText], @"payload",
                                  Nil];
    
    NSData *jsonData = [finalPayload JSONDataWithOptions:JKSerializeOptionNone error:Nil];
    
    NSAssert(jsonData, @"Unable to create JSON payload");

#ifdef DEBUG
    if (!beeblex._useSSL) {
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            NSLog(@"Warning: Beeblex is not using HTTPS to connect to the server, most likely due to export compliance reasons. This is not necessarily a problem, but we thought you should know.");
        });
    }
#endif

    NSURL *URL = [NSURL URLWithString:[NSString stringWithFormat:@"%@/app/%@/verify",
                                       beeblex._currentBaseURL,
                                       beeblex.apiKey]];
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:URL];
    request.HTTPMethod = @"POST";
    request.HTTPBody = jsonData;
    
    [NSURLConnection sendAsynchronousRequest:request
                                       queue:[NSOperationQueue mainQueue]
                           completionHandler:^(NSURLResponse *response, NSData *data, NSError *error) {
                               if (!data || error) {
                                   errorBlock(NSLocalizedString(@"Unable to contact the Beeblex validation server.", Nil));
                                   return;
                               }
                               
                               NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *) response;
                               
                               if (httpResponse.statusCode > 399 && httpResponse.statusCode < 500) {
                                   errorBlock([NSString stringWithFormat:NSLocalizedString(@"Server error %d.", Nil), httpResponse.statusCode]);
                                   return;
                               }
                               
                               if (httpResponse.statusCode > 499 && httpResponse.statusCode < 600) {
                                   errorBlock([NSString stringWithFormat:NSLocalizedString(@"Client error %d.", Nil), httpResponse.statusCode]);
                                   return;
                               }
                               
                               data = [_BBXBase64 dataFromBase64String:[[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding]];
                               
                               if (!data.length) {
                                   errorBlock(NSLocalizedString(@"Unable to decrypt the validation data.", Nil));
                                   return;
                               }
                               
                               NSData *resultData = [self _processedDataFromData:data withSymmetricKey:symmetricKey encrypt:NO];
                               
                               if (!resultData) {
                                   errorBlock(NSLocalizedString(@"Unable to decrypt the data return by the Beeblex server.", Nil));
                                   return;
                               }
                               
                               id result = [[BBXJSONDecoder decoder] objectWithData:resultData
                                                                              error:&error];
                               
                               if (!result || (![result isKindOfClass:[NSDictionary class]] && ![result isKindOfClass:[NSArray class]])) {
                                   errorBlock(NSLocalizedString(@"Unable to decode the data returned by the Beeblex server.", Nil));
                                   return;
                               }
                               
                               completionBlock(result, Nil);
                           }];

}


@end
