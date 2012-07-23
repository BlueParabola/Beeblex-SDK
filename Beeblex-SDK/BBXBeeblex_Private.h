//
//  BBXBeeblex_Private.h
//  beeblex
//
//  Created by Marco Tabini on 2012-07-16.
//  Copyright (c) 2012 Blue Parabola, LLC. All rights reserved.
//

#import "BBXBeeblex.h"


@interface BBXBeeblex ()


@property (nonatomic) BOOL _useSSL;


+ (BBXBeeblex *) _globalInstance;

+ (NSString *) _baseURL;
+ (NSString *) _baseSecureURL;


- (NSString *) _currentBaseURL;


@end
