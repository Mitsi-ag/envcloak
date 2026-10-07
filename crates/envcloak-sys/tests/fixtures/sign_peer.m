// Test-only signer: selects an identity in one explicit disposable keychain.
// SecCodeSigner's SPI avoids codesign's trusted-identity search without adding
// the fixture certificate to the user's trust settings. Nothing ships this.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <arpa/inet.h>
extern const CFStringRef kSecCodeSignerIdentity;
extern const CFStringRef kSecCodeSignerIdentifier;
extern const CFStringRef kSecCodeSignerFlags;
extern const CFStringRef kSecCodeSignerEntitlements;
extern const CFStringRef kSecCodeSignerRequireTimestamp;
extern OSStatus SecCodeSignerCreate(CFDictionaryRef, uint32_t, CFTypeRef *);
extern OSStatus SecCodeSignerAddSignature(CFTypeRef, SecStaticCodeRef, uint32_t);
static void check(OSStatus status) {
    if (status) { fprintf(stderr, "fixture signer status: %d\n", (int)status); exit(1); }
}
int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc != 7) return 2;
        SecKeychainRef keychain = NULL;
        check(SecKeychainOpen(argv[1], &keychain));
        NSData *data = [NSData dataWithContentsOfFile:@(argv[2])];
        if (!data) return 3;
        SecCertificateRef certificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)data);
        if (!certificate) return 4;
        SecIdentityRef identity = NULL;
        check(SecIdentityCreateWithCertificate(keychain, certificate, &identity));
        NSMutableDictionary *parameters = [@{
            (__bridge NSString *)kSecCodeSignerIdentity: (__bridge id)identity,
            (__bridge NSString *)kSecCodeSignerIdentifier: @(argv[4]),
            (__bridge NSString *)kSecCodeSignerFlags: @(atoi(argv[5])),
            (__bridge NSString *)kSecCodeSignerRequireTimestamp: @NO,
        } mutableCopy];
        if (strlen(argv[6])) {
            NSData *entitlements = [NSData dataWithContentsOfFile:@(argv[6])];
            if (!entitlements) return 5;
            uint32_t header[2] = { htonl(0xfade7171), htonl((uint32_t)entitlements.length + 8) };
            NSMutableData *blob = [NSMutableData dataWithBytes:header length:8];
            [blob appendData:entitlements];
            parameters[(__bridge NSString *)kSecCodeSignerEntitlements] = blob;
        }
        CFTypeRef signer = NULL;
        check(SecCodeSignerCreate((__bridge CFDictionaryRef)parameters, 0, &signer));
        SecStaticCodeRef code = NULL;
        check(SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:@(argv[3])], 0, &code));
        check(SecCodeSignerAddSignature(signer, code, 0));
        CFRelease(code); CFRelease(signer); CFRelease(identity); CFRelease(certificate); CFRelease(keychain);
    }
    return 0;
}
