//
//  ViewController.m
//  ios-chop-tester
//
//  Created by Fabian Freyer on 10.01.23.
//

#import "ViewController.h"
#include "chop.hpp"
#import <UserNotifications/UserNotifications.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    UNUserNotificationCenter* center = [UNUserNotificationCenter currentNotificationCenter];
    [center requestAuthorizationWithOptions:(UNAuthorizationOptionAlert + UNAuthorizationOptionSound)
       completionHandler:^(BOOL granted, NSError * _Nullable error) {
        NSLog(@"User notifications granted: %d", granted);
    }];
    
}


- (IBAction)trigger:(id)sender {
    poc();
}
@end
