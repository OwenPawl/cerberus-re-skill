#import <Foundation/Foundation.h>

@interface CodexProbe : NSObject
- (NSString *)runWithInput:(NSString *)input;
@end

@implementation CodexProbe
- (NSString *)runWithInput:(NSString *)input {
    NSLog(@"CodexProbe input: %@", input);
    return [input stringByAppendingString:@"-validated"];
}
@end

int main(void) {
    @autoreleasepool {
        CodexProbe *probe = [CodexProbe new];
        NSString *result = [probe runWithInput:@"ghidra"];
        NSLog(@"CodexProbe result: %@", result);
    }
    return 0;
}
