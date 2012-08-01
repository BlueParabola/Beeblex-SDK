//
//  _BBXEncryptedTransaction.h
//  Beeblex-SDK
//
//  Created by Marco Tabini on 2012-07-19.
//  Copyright (c) 2012 Blue Parabola, LLC. All rights reserved.
//

#import <Foundation/Foundation.h>


#define _BBXEncryptedTransactionErrorCodeKey @"_BBXEncryptedTransactionErrorCodeKey"


typedef void(^BBXEncryptedTransactionResultBlock)(id response, NSError *error);


@interface _BBXEncryptedTransaction : NSObject


+ (void) processTransactionWithPayload:(NSData *) payload errorDomain:(NSString *) errorDomain callback:(BBXEncryptedTransactionResultBlock) callback;


@end
