//
//  _BBXBase64.h
//  Beeblex-SDK
//
//  Created by Marco Tabini on 2012-07-23.
//  Copyright (c) 2012 Blue Parabola, LLC. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface _BBXBase64 : NSObject


+ (NSData *)dataFromBase64String:(NSString *)aString;
+ (NSString *)base64EncodedStringFromData:(NSData *) data;


@end
