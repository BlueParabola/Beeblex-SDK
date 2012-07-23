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

#import "_BBXCrypto.h"

#import "JSONKit/_BBXJSONKit.h"


@implementation _BBXEncryptedTransaction


+ (void) processTransactionWithPayload:(NSData *)payload errorDomain:(NSString *)errorDomain callback:(BBXEncryptedTransactionResultBlock)completionBlock {
    BBXBeeblex *beeblex = [BBXBeeblex _globalInstance];
    
    void(^errorBlock)(NSString *errorString) = ^(NSString *errorString) {
        NSError *error = [[NSError alloc] initWithDomain:errorDomain
                                                    code:BBXBeeblexErrorCodes.serverError
                                                userInfo:[NSDictionary dictionaryWithObject:NSLocalizedString(@"The encryption engine cannot be initialized.", Nil)
                                                                                     forKey:NSLocalizedDescriptionKey]];
        completionBlock(Nil, error);
    };
        
    NSData *symmetricKey = [_BBXCrypto getKeyDataWithLength:8];
    
    NSAssert1(symmetricKey.length == 8, @"The secret key should be 8 bytes; %d found instead", symmetricKey.length);
    
    _BBXCrypto *crypto = [[_BBXCrypto alloc] initWithSymmetricKey:symmetricKey];
    
    if (!crypto) {
        errorBlock(NSLocalizedString(@"The encryption engine cannot be initialized.", Nil));
        return;
    }
    
    [crypto setClearTextWithData:payload];
    NSData *cypherText = [crypto encrypt:@"blowfish"];
    
    if (!cypherText) {
        errorBlock(NSLocalizedString(@"Cannot generate an encryption key.", Nil));
        return;
    }
    
    
    crypto = [[_BBXCrypto alloc] initWithPublicKey:[beeblex.publicKey dataUsingEncoding:NSASCIIStringEncoding]];
    
    if (!crypto) {
        errorBlock(NSLocalizedString(@"Cannot generate public key.", Nil));
        return;
    }
    
    [crypto setClearTextWithData:symmetricKey];
    
    NSData *signature = [crypto signPublic];
    
    if (!signature) {
        errorBlock(NSLocalizedString(@"Cannot encrypt symmetric key.", Nil));
        return;
    }
    
    NSDictionary *finalPayload = [NSDictionary dictionaryWithObjectsAndKeys:
                                  [_BBXCrypto encodeBase64:signature WithNewlines:NO], @"signature",
                                  [_BBXCrypto encodeBase64:cypherText WithNewlines:NO], @"payload",
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
                               
                               data = [_BBXCrypto decodeBase64:data WithNewLines:NO];
                               
                               if (!data.length) {
                                   errorBlock(NSLocalizedString(@"Unable to decrypt the validation data.", Nil));
                                   return;
                               }
                               
                               _BBXCrypto *crypto = [[_BBXCrypto alloc] initWithSymmetricKey:symmetricKey];
                               
                               if (!crypto) {
                                   errorBlock(NSLocalizedString(@"The encryption engine cannot be initialized.", Nil));
                                   return;
                               }
                               
                               [crypto setCipherText:data];
                               
                               NSData *resultData = [crypto decrypt:@"blowfish"];
                               
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
