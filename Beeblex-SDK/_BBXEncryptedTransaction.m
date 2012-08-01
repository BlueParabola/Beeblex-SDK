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

#import "blowfish.h"


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


static inline int32_t _bbxSwapInt32(int32_t data) {
    return ((data & 0xFF000000) >> 24) |
    ((data & 0x00FF0000) >>  8) |
    ((data & 0x0000FF00) <<  8) |
    ((data & 0x000000FF) << 24);
}


static inline void _bbxXor(unsigned char *dataPtr, unsigned char *xorPtr) {
    for (NSInteger index = 0; index < sizeof(int64_t); index++) {
        dataPtr[index] = dataPtr[index] ^ xorPtr[index];
    }
}


+ (NSData *) _processedDataFromData:(NSData *) data withSymmetricKey:(NSData *) signature encrypt:(BOOL) encrypt {
    unsigned char symmetricKey[16];
    unsigned char iv[16];
    
    CC_MD5(signature.bytes, signature.length, symmetricKey);
    
    NSMutableData *hash = [NSMutableData dataWithBytes:symmetricKey length:16];
    [hash appendData:signature];
    
    CC_MD5(hash.bytes, hash.length, iv);
    
    unsigned char padding;
    
    if (encrypt) {
        padding = sizeof(int64_t) - (data.length % sizeof(int64_t));
        
        if (!padding) {
            padding = sizeof(int64_t);
        }
    } else {
        if (data.length % sizeof(int64_t) != 0) {
            NSLog(@"Invalid input data size %d", data.length);
            return Nil;
        }
        
        padding = 0;
    }
    
    unsigned long outputLength = data.length + padding;
    unsigned char *outputData = malloc(outputLength);
    
    NSAssert(outputData, @"Memory allocation error.");

    // Copy input into work buffer
    
    memcpy(outputData, data.bytes, data.length);

    // Allocate blowfish structures
    
    BLOWFISH_CTX *ctx = malloc(sizeof(BLOWFISH_CTX));
    
    NSAssert(ctx, @"Memory allocation error.");
    
    // Apply PKCS7 padding if appropriate
    
    for (NSInteger index = data.length; index < outputLength; index++) {
        outputData[index] = padding;
    }
    
    // Encrypt or decrypt using CBC
    
    int64_t *pointer = (int64_t *) outputData;
    int64_t *endPointer = ((int64_t *) outputData) + outputLength / sizeof(int64_t);
    
    int64_t xor = ((int64_t *) iv)[0];
    int64_t encrypted;
    
    Blowfish_Init(ctx, symmetricKey, 16);
    
    while (pointer < endPointer) {
        if (encrypt) {
            _bbxXor((unsigned char *) pointer, (unsigned char *) &xor);
        } else {
            encrypted = *pointer;
        }
        
        unsigned long *left = (unsigned long *) pointer;
        unsigned long *right = ((unsigned long *) pointer + 1);
        
        *left = _bbxSwapInt32(*left);
        *right = _bbxSwapInt32(*right);
        
        if (encrypt) {
            Blowfish_Encrypt(ctx, left, right);
        } else {
            Blowfish_Decrypt(ctx, left, right);
        }
        
        *left = _bbxSwapInt32(*left);
        *right = _bbxSwapInt32(*right);
        

        if (!encrypt) {
            _bbxXor((unsigned char *) pointer, (unsigned char *) &xor);
            xor = encrypted;
        } else {
            xor = *pointer;
        }
                
        pointer += 1;
    }
    
    // Verify padding if decrypting
    
    if (!encrypt) {
        padding = outputData[outputLength - 1];
        
        if (padding > (sizeof(int64_t) + 1) || padding < 1 || padding > outputLength - 1) {
            free(outputData);
            free(ctx);
            
            NSLog(@"Invalid padding found.");
            
            return Nil;
        }
        
        unsigned char *ptr = outputData + outputLength - (padding % (sizeof(int64_t) + 1));
        unsigned char index = 0;
        
        for (index = 0; index < (padding % (sizeof(int64_t) + 1)); index++) {
            if (ptr[index] != padding) {
                free(outputData);
                free(ctx);
                
                NSLog(@"Invalid padding found.");
                
                return Nil;
            }
        }
        
        outputLength -= padding;
    }
    
    NSData *result = [NSData dataWithBytes:outputData length:outputLength];

    free (outputData);
    memset(ctx, sizeof(BLOWFISH_CTX), 0);
    free(ctx);
    
    return result;
}


+ (void) processTransactionWithPayload:(NSData *)payload errorDomain:(NSString *)errorDomain callback:(BBXEncryptedTransactionResultBlock)completionBlock {
    BBXBeeblex *beeblex = [BBXBeeblex _globalInstance];
    
    void(^errorBlock)(NSString *errorString, NSInteger errorCode) = ^(NSString *errorString, NSInteger errorCode) {
        NSError *error = [[NSError alloc] initWithDomain:errorDomain
                                                    code:BBXBeeblexErrorCodes.serverError
                                                userInfo:[NSDictionary dictionaryWithObjectsAndKeys:
                                                          errorString, NSLocalizedDescriptionKey,
                                                          [NSNumber numberWithInteger:errorCode], _BBXEncryptedTransactionErrorCodeKey,
                                                          nil]];
        
        completionBlock(Nil, error);
    };
        
    NSData *symmetricKey = [self.class _getKeyDataWithLength:8];
    
    NSAssert1(symmetricKey.length == 8, @"The secret key should be 8 bytes; %d found instead", symmetricKey.length);
    
    NSData *cypherText = [self _processedDataFromData:payload withSymmetricKey:symmetricKey encrypt:YES];
    
    if (!cypherText) {
        errorBlock(NSLocalizedString(@"Cannot encrypt main payload using a symmetric algorithm.", Nil), -1);
        return;
    }

    unsigned long length = 1024; // Ought to be more than enough
    unsigned char *encryptedData = malloc(length);
    
    NSAssert(encryptedData, @"Memory allocation error.");
    
    OSStatus error = SecKeyEncrypt(beeblex.publicKey,
                                   kSecPaddingPKCS1,
                                   symmetricKey.bytes,
                                   symmetricKey.length,
                                   encryptedData,
                                   &length);
    
    if (error) {
        free(encryptedData);
        errorBlock([NSString stringWithFormat:NSLocalizedString(@"Unable to sign transaction: OSStatus error %ld.", Nil), error], -1);
        return;
    }

    NSData *signature = [NSData dataWithBytes:encryptedData length:length];
    
    free(encryptedData);
    
    if (!signature) {
        errorBlock(NSLocalizedString(@"Cannot encrypt symmetric key.", Nil), -1);
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
                                   errorBlock(NSLocalizedString(@"Unable to contact the Beeblex validation server.", Nil), -1);
                                   return;
                               }
                               
                               NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *) response;
                               
                               if (httpResponse.statusCode > 399 && httpResponse.statusCode < 500) {
                                   errorBlock([NSString stringWithFormat:NSLocalizedString(@"Server error %d.", Nil), httpResponse.statusCode],
                                              httpResponse.statusCode);
                                   return;
                               }
                               
                               if (httpResponse.statusCode > 499 && httpResponse.statusCode < 600) {
                                   errorBlock([NSString stringWithFormat:NSLocalizedString(@"Client error %d.", Nil), httpResponse.statusCode],
                                              httpResponse.statusCode);
                                   return;
                               }
                               
                               data = [_BBXBase64 dataFromBase64String:[[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding]];
                               
                               if (!data.length) {
                                   errorBlock(NSLocalizedString(@"Unable to decrypt the validation data.", Nil), -1);
                                   return;
                               }
                               
                               NSData *resultData = [self _processedDataFromData:data withSymmetricKey:symmetricKey encrypt:NO];
                               
                               if (!resultData) {
                                   errorBlock(NSLocalizedString(@"Unable to decrypt the data returned by the Beeblex server.", Nil), -1);
                                   return;
                               }
                               
                               id result = [[BBXJSONDecoder decoder] objectWithData:resultData
                                                                              error:&error];
                               
                               if (!result || (![result isKindOfClass:[NSDictionary class]] && ![result isKindOfClass:[NSArray class]])) {
                                   errorBlock(NSLocalizedString(@"Unable to decode the data returned by the Beeblex server.", Nil), -1);
                                   return;
                               }
                               
                               completionBlock(result, Nil);
                           }];

}


@end
