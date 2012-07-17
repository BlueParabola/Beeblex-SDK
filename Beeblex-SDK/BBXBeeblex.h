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
    
    // An invalid API Key was provided
    
    __unsafe_unretained NSString *invalidApiKey;
    
    // An invalid payment transaction was sent. Usually.
    // That means the transaction is not completed or restored.
    
    __unsafe_unretained NSString *invalidSKPaymentTransaction;
    
    // Thrown when you attempt to use an instance of BBXIAPTransaction
    // more than once. You should create a new instance each time
    // you want to verify a receipt.
    
    __unsafe_unretained NSString *cannotRecycleVerificationRequest;
    
} BBXBeeblexExceptionNames;


@interface BBXBeeblex : NSObject

// The unique API identifier generated from the API Key

@property (nonatomic, readonly) NSString *apiKey;

// The RSA public key generated from the API key

@property (nonatomic, readonly) NSString *publicKey;


// You should call this method from your app's application
// delegate using the API key for this particular app.

+ (BOOL) initializeWithAPIKey:(NSString *) apiKey;

// Returns the library's current version number.

+ (NSString *) versionNumber;


@end
