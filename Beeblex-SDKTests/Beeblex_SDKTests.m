//
//  Beeblex_SDKTests.m
//  Beeblex-SDKTests
//
//  Created by Marco Tabini on 2012-07-17.
//  Copyright (c) 2012 Blue Parabola, LLC. All rights reserved.
//

#import "Beeblex_SDKTests.h"

#import "BBXBeeblex.h"
#import "BBXBeeblex_Private.h"
#import "BBXIAPTransaction.h"

#import "_BBXJSONKit.h"

@implementation Beeblex_SDKTests

- (void)setUp {
    [super setUp];
        
    [BBXBeeblex initializeWithAPIKey:@"Y2FiZDA2NDM3NGRhNmEzNzI5ZjkwMTNhM2E1YzI5ZWY0NjVmOTkyOTlhNWI1ZjM3YThiODViZjEyZWNlZTI2NzRmMWE4ZmI5ZWE3MmE0ZTE4MDQyY2Q3Y2IwZGY0MDQ5M2I4YWZlYjAzZWIzNGMzZWUwNjgxMDdkNGJiNmQ5Y2EsLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FEV1FscmtxdHhjRnNYRTlDc1Uya2h2ckx0aQp2N2pZWmVaSWJudG9UWmdTWXBSSFFNYS9DVE5odFNiM3VpNkNSM0JMd0pZaWJ2SHV4NWpISWpXNzkrMzJrUWpwCmphdTJoUDZXcFBDYTBodTVrbFF2UTJyakhZcEV0dDZHM1lJR3NDYU9oeC9lS25oOGlpMWdsa294bkorL0xtMVcKdlFWRkFpSll6RFBEZjB4OVR3SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ=="];
}


- (void)testInitialization {
    BBXBeeblex *beeblex = [BBXBeeblex _globalInstance];
        
    STAssertEqualObjects(beeblex.apiKey,
                         @"cabd064374da6a3729f9013a3a5c29ef465f99299a5b5f37a8b85bf12ecee2674f1a8fb9ea72a4e18042cd7cb0df40493b8afeb03eb34c3ee068107d4bb6d9ca",
                         @"Invalid API Key");
    
    STAssertEqualObjects(beeblex.publicKey,
                         @"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDWQlrkqtxcFsXE9CsU2khvrLti\nv7jYZeZIbntoTZgSYpRHQMa/CTNhtSb3ui6CR3BLwJYibvHux5jHIjW79+32kQjp\njau2hP6WpPCa0hu5klQvQ2rjHYpEtt6G3YIGsCaOhx/eKnh8ii1glkoxnJ+/Lm1W\nvQVFAiJYzDPDf0x9TwIDAQAB\n-----END PUBLIC KEY-----",
                         @"Invalid Public Key");
}


- (void) testTransaction {
    STAssertEquals([BBXIAPTransaction canValidateTransactions],
                   YES,
                   @"Cannot process transactions");
    
    SKPaymentTransaction *iapTransaction = [[SKPaymentTransaction alloc] init];
    
    BBXIAPTransaction *transaction = [[BBXIAPTransaction alloc] initWithTransaction:iapTransaction];
    
    [transaction validateWithCompletionBlock:^(NSError *error) {
        NSLog(@"ERR: %@", error);
        
        STAssertNil(error, @"Validation completed with an error.");
    }];
}

- (void) testJSON {

    NSDictionary *payload = @{
        @"transactionData"  : @"fggijo254325uh3450h2p5h435983h459p2345235353458p9hefg",
        @"submissionDate"   : @((NSUInteger) [[NSDate date] timeIntervalSince1970]),
        @"transactionId"    : @"testID",
        @"useSandbox"       : @(YES)
    };
    
    NSData *ns = [NSJSONSerialization dataWithJSONObject:payload
                                                 options:0
                                                   error:nil];
    NSData *jk = [payload JSONDataWithOptions:JKSerializeOptionNone error:nil];
    
    STAssertEqualObjects(ns, jk, @"JSONKit and NSJSON produced different data.");

    // Now see if we can recreate the original dictionary from the JSON data
    
    NSDictionary *nsdict = [NSJSONSerialization JSONObjectWithData:ns
                                                           options:0
                                                             error:nil];
    STAssertEqualObjects(payload, nsdict, @"NSJSON produced a different object from the JSON data: %@", nsdict);
    
    NSDictionary *jkdict = [[BBXJSONDecoder decoder] objectWithData:jk];
    
    STAssertEqualObjects(payload, jkdict, @"JSONKit produced a different object from the JSON data: %@", jkdict);
    
    STAssertEqualObjects(nsdict, jkdict, @"NSJSON and JSONKit disagree on the objects produced from their data: %@ != %@", nsdict, jkdict);
    
    NSLog(@"NSJSON: %@\n\nJSONKit: %@", nsdict, jkdict);
}

@end
