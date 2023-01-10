//
//  main.m
//  ios-chop-tester
//
//  Created by Fabian Freyer on 10.01.23.
//
#import <UserNotifications/UserNotifications.h>
#import <UIKit/UIKit.h>
#import "AppDelegate.h"

void Success(void);
void Failure(void);

void Log(const char *message)
{
    NSLog(@"%s", message);
}

void Success() {
    UNMutableNotificationContent* content = [[UNMutableNotificationContent alloc] init];
    content.title = @"CHOP";
    content.body = @"CHOP attack successful!";
    content.sound = [UNNotificationSound defaultSound];
    content.interruptionLevel = UNNotificationInterruptionLevelTimeSensitive;
    UNTimeIntervalNotificationTrigger* trigger = [UNTimeIntervalNotificationTrigger
                triggerWithTimeInterval:1 repeats:NO];

    UNNotificationRequest* req = [UNNotificationRequest requestWithIdentifier:[NSUUID UUID].UUIDString
                                                                          content:content
                                                                          trigger:trigger];
    UNUserNotificationCenter* c = [UNUserNotificationCenter currentNotificationCenter];
    [c addNotificationRequest:req withCompletionHandler:^(NSError* e){NSLog(@"%@", e);}];

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"CHOP Attack"
                                                                    message:@"Successful"
                                                             preferredStyle:(UIAlertControllerStyleAlert)];
    [[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:alert
                                                                                 animated:YES
                                                                               completion:^{
                                                                               }];
}

void Failure() {
    UNMutableNotificationContent* content = [[UNMutableNotificationContent alloc] init];
    content.title = @"CHOP";
    content.body = @"CHOP attack failed!";
    content.sound = [UNNotificationSound defaultSound];
    content.interruptionLevel = UNNotificationInterruptionLevelTimeSensitive;
    UNTimeIntervalNotificationTrigger* trigger = [UNTimeIntervalNotificationTrigger
                triggerWithTimeInterval:1 repeats:NO];

    UNNotificationRequest* req = [UNNotificationRequest requestWithIdentifier:[NSUUID UUID].UUIDString
                                                                          content:content
                                                                          trigger:trigger];
    UNUserNotificationCenter* c = [UNUserNotificationCenter currentNotificationCenter];
    [c addNotificationRequest:req withCompletionHandler:^(NSError* e){NSLog(@"%@", e);}];

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"CHOP Attack"
                                                                    message:@"Successful"
                                                             preferredStyle:(
                                                                             UIAlertControllerStyleAlert)];
    [[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:alert
                                                                                 animated:YES
                                                                               completion:^{
                                                                               }];
}

int main(int argc, char * argv[]) {
    NSString * appDelegateClassName;
    @autoreleasepool {
        // Setup code that might create autoreleased objects goes here.
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
