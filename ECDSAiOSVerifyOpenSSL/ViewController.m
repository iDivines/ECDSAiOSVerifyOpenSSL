//
//  ViewController.m
//  ECDSAiOSVerifyOpenSSL
//
//  Created by iDivines on 2020/4/24.
//  Copyright © 2020 idivines. All rights reserved.
//

#import "ViewController.h"
#import <openssl/ec.h>
#import <openssl/objects.h>
#import <openssl/bn.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/SecKey.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self ecdsaTest];
}

- (void)ecdsaTest{
    int        ret;
    int        nid;
    ECDSA_SIG *sig;
    EC_KEY    *eckey;
    unsigned char digest [20];
    size_t dataToSignLen = 20;
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(digest, (uint32_t)dataToSignLen, hash);
    
    //1.使用openssl创建椭圆曲线和KEY
    //特别注意这里使用的曲线是prime256v1，和ios中的kSecKeyAlgorithmECDSASignatureMessageX962SHA256对应
    nid = OBJ_sn2nid("prime256v1");
    eckey = EC_KEY_new_by_curve_name(nid);
    if (eckey == NULL){
        return;
    }
    
    if (!EC_KEY_generate_key(eckey)){
        return;
    }

    //2.使用openssl对数据进行签名
    sig = ECDSA_do_sign(hash, CC_SHA256_DIGEST_LENGTH, eckey);
    if (sig == NULL){
        return;
    }
    
    //3.使用openssl验证签名
    ret = ECDSA_do_verify(hash, CC_SHA256_DIGEST_LENGTH, sig, eckey);
    if(ret != 1){
        return;
    }
    
    //4.获取openssl的签名结果
    unsigned char signChar[100] = {0};
    unsigned char *p = signChar;
    int len = i2d_ECDSA_SIG(sig, &p);
    NSData *signature = [NSData dataWithBytes:signChar length:len];
    NSLog(@"%@",signature);
    
    //5.获取公钥
    const EC_POINT *pubkey = EC_KEY_get0_public_key(eckey);
    const EC_GROUP *ec_group = EC_KEY_get0_group(eckey);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    
    if (EC_POINT_get_affine_coordinates_GFp(ec_group, pubkey, x, y, NULL)) {
        printf("公钥:\n");
        BN_print_fp(stdout, x);
        putc('\n', stdout);
        BN_print_fp(stdout, y);
        putc('\n', stdout);
    }
    
    unsigned char char_x[32] = {0};
    unsigned char char_y[32] = {0};
    BN_bn2bin(x,char_x);
    BN_bn2bin(y,char_y);
    
    unsigned char pubkeyChar[65] = {0};
    pubkeyChar[0] = 0x04;
    for(int i=0; i<32; i++){
        pubkeyChar[i+1] = char_x[i];
        pubkeyChar[i+1+32] = char_y[i];
    }
    NSData *pubKeyData = [NSData dataWithBytes:pubkeyChar length:65];
    NSLog(@"%@",pubKeyData);
    
    //6.产生IOS使用的公钥对象
    NSDictionary *dic = @{
                          (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeEC,
                          (__bridge id)kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPublic,
                          (__bridge id)kSecAttrKeySizeInBits : @(256)
                          };
    
    NSError *error = nil;
    SecKeyRef pubSecKey = SecKeyCreateWithData((CFDataRef)pubKeyData, (CFDictionaryRef)dic, (void *)&error);
    if(error){
        NSLog(@"产生IOS使用的公钥对象失败");
        return;
    }
    
    //4.验证签名
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
    BOOL canEncrypt = SecKeyIsAlgorithmSupported(pubSecKey, kSecKeyOperationTypeVerify, algorithm);
    if(!canEncrypt){
        return;
    }
    
    NSData *signedData = [NSData dataWithBytes:digest length:20];
    SecKeyVerifySignature(pubSecKey, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, (CFDataRef)signedData, (CFDataRef)signature, (void *)&error);
    if(error){
        NSLog(@"IOS验证签名失败");
        return;
    }
    
    NSLog(@"IOS验证签名成功");
}

@end
