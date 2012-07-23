//
//  BBXBeeblex.h
//  beeblex
//
//  Created by Marco Tabini on 2012-07-16.
//  Copyright (c) 2012 Blue Parabola, LLC. All rights reserved.
//

#import <Foundation/Foundation.h>

// Exception names used by Beeblex. You can use
// this struct to identify possible types of exceptions
// thrown by the system

extern const struct BBXBeeblexExceptionNames {
    
    __unsafe_unretained NSString *configurationTransactionException;
    
} BBXBeeblexExceptionNames;


extern const struct BBXBeeblexErrorCodes {
    
    NSInteger serverError;
    
    NSInteger iapValidationError;
    
} BBXBeeblexErrorCodes;


@interface BBXBeeblex : NSObject

// The unique API identifier generated from the API Key

@property (nonatomic, readonly) NSString *apiKey;

// The RSA public key generated from the API key

@property (nonatomic, readonly) SecKeyRef publicKey;


// You should call this method from your app's application
// delegate using the API key for this particular app.

+ (BOOL) initializeWithAPIKey:(NSString *) apiKey;

// Returns the library's current version number.

+ (NSString *) versionNumber;

// Pass YES to this method to turn SSL encryption between
// the SDK and Beeblex's servers

+ (void) setUseSSL:(BOOL) useSSL;


@end
