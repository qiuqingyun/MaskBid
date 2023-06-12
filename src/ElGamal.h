// ElGamal加密相关操作
#pragma once
#include "base.h"
#include "ec.h"

class ElGamal_ciphertext
{
public:
    EC_POINT *C1 = nullptr;
    EC_POINT *C2 = nullptr;

    // 构造函数
    ElGamal_ciphertext() {}

    // 构造函数
    ElGamal_ciphertext(EC_GROUP *curve)
    {
        C1 = EC_POINT_new(curve);
        C2 = EC_POINT_new(curve);
    }

    // ElGamal_ciphertext(EC_GROUP *curve, const Messages::Msg_ElGamal_ciphertext &message, BN_CTX *ctx)
    // {
    //     BN_CTX_start(ctx);
    //     C1 = EC_POINT_deserialize(curve, message.c1(), ctx);
    //     C2 = EC_POINT_deserialize(curve, message.c2(), ctx);
    //     BN_CTX_end(ctx);
    // }

    // 拷贝构造函数
    ElGamal_ciphertext(EC_GROUP *curve, EC_POINT *C1, EC_POINT *C2)
    {
        this->C1 = EC_POINT_dup(C1, curve);
        this->C2 = EC_POINT_dup(C2, curve);
    }

    // 深拷贝构造函数
    ElGamal_ciphertext(EC_GROUP *curve, ElGamal_ciphertext *ciphertext)
    {
        C1 = EC_POINT_dup(ciphertext->C1, curve);
        C2 = EC_POINT_dup(ciphertext->C2, curve);
    }

    // 释放内存
    ~ElGamal_ciphertext()
    {
        EC_POINT_free(C1);
        EC_POINT_free(C2);
    }

    std::string to_string(EC_GROUP *curve, BN_CTX *ctx)
    {
        std::stringstream ss;
        ss << "(" << EC_POINT_point2hex(curve, C1, POINT_CONVERSION_COMPRESSED, ctx) << ", " << EC_POINT_point2hex(curve, C2, POINT_CONVERSION_COMPRESSED, ctx) << ")";
        return ss.str();
    }

    // 获取字节数
    size_t get_size(EC_GROUP *curve, BN_CTX *ctx)
    {
        return EC_POINT_point2oct(curve, C1, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx) + EC_POINT_point2oct(curve, C2, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    }

    // 序列化
    // Messages::Msg_ElGamal_ciphertext *serialize(EC_GROUP *curve, BN_CTX *ctx)
    // {
    //     BN_CTX_start(ctx);
    //     Messages::Msg_ElGamal_ciphertext *message = new Messages::Msg_ElGamal_ciphertext();
    //     message->set_c1(EC_POINT_serialize(curve, C1, ctx));
    //     message->set_c2(EC_POINT_serialize(curve, C2, ctx));
    //     BN_CTX_end(ctx);
    //     return message;
    // }

    // void insert(EC_GROUP *curve, Messages::Msg_ElGamal_ciphertext *target, BN_CTX *ctx)
    // {
    //     Messages::Msg_ElGamal_ciphertext *serialized = serialize(curve, ctx);
    //     target->CopyFrom(*serialized);
    //     delete serialized;
    //     serialized = nullptr;
    // }
};

int ElGamal_ciphertext_cmp(EC_GROUP *curve, ElGamal_ciphertext *ciphertext1, ElGamal_ciphertext *ciphertext2, BN_CTX *ctx)
{
    int result = EC_POINT_cmp(curve, ciphertext1->C1, ciphertext2->C1, ctx);
    if (result != 0)
        return result;
    return EC_POINT_cmp(curve, ciphertext1->C2, ciphertext2->C2, ctx);
}

// ElGamal同态加法
void ElGamal_add(EC_GROUP *curve, ElGamal_ciphertext *result, ElGamal_ciphertext *ciphertext1, ElGamal_ciphertext *ciphertext2, BN_CTX *ctx)
{
    if (result->C1 == nullptr)
        result->C1 = EC_POINT_new(curve);
    if (result->C2 == nullptr)
        result->C2 = EC_POINT_new(curve);
    EC_POINT_add(curve, result->C1, ciphertext1->C1, ciphertext2->C1, ctx);
    EC_POINT_add(curve, result->C2, ciphertext1->C2, ciphertext2->C2, ctx);
}

// ElGamal同态减法
void ElGamal_sub(EC_GROUP *curve, ElGamal_ciphertext *result, ElGamal_ciphertext *ciphertext1, ElGamal_ciphertext *ciphertext2, BN_CTX *ctx)
{
    if (result->C1 == nullptr)
        result->C1 = EC_POINT_new(curve);
    if (result->C2 == nullptr)
        result->C2 = EC_POINT_new(curve);
    // 将ciphertext2取反
    ElGamal_ciphertext *temp = new ElGamal_ciphertext(curve, ciphertext2);
    EC_POINT_invert(curve, temp->C1, ctx);
    EC_POINT_invert(curve, temp->C2, ctx);
    // ciphertext1 + (-ciphertext2)
    EC_POINT_add(curve, result->C1, ciphertext1->C1, temp->C1, ctx);
    EC_POINT_add(curve, result->C2, ciphertext1->C2, temp->C2, ctx);
    // 释放内存
    delete temp;
    temp = nullptr;
}

// ElGamal标量同态乘法
void ElGamal_mul(EC_GROUP *curve, ElGamal_ciphertext *result, ElGamal_ciphertext *ciphertext, BIGNUM *scalar, BN_CTX *ctx)
{
    if (result->C1 == nullptr)
        result->C1 = EC_POINT_new(curve);
    if (result->C2 == nullptr)
        result->C2 = EC_POINT_new(curve);
    EC_POINT_mul(curve, result->C1, NULL, ciphertext->C1, scalar, ctx);
    EC_POINT_mul(curve, result->C2, NULL, ciphertext->C2, scalar, ctx);
}

// 生成密钥对
void ElGamal_keygen(W1 *w1, EC_POINT **pk, BIGNUM **sk, BN_CTX *ctx)
{
    // 生成私钥
    *sk = BN_new();
    BN_rand(*sk, 256, -1, 0);
    // 生成公钥pk=sk*base
    *pk = EC_POINT_new(w1->get_curve());
    EC_POINT_mul(w1->get_curve(), *pk, NULL, w1->get_H(), *sk, ctx);
}

// 加密函数
ElGamal_ciphertext *ElGamal_encrypt(W1 *w1, BIGNUM *plaintext, BIGNUM *r, BN_CTX *ctx)
{
    ElGamal_ciphertext *ciphertext = new ElGamal_ciphertext;
    ciphertext->C1 = EC_POINT_new(w1->get_curve());
    ciphertext->C2 = EC_POINT_new(w1->get_curve());
    // 计算C1 = plaintext*G + r*Y
    EC_POINT *temp1 = EC_POINT_new(w1->get_curve());
    EC_POINT *temp2 = EC_POINT_new(w1->get_curve());
    EC_POINT_mul(w1->get_curve(), temp1, NULL, w1->get_G(), plaintext, ctx);
    EC_POINT_mul(w1->get_curve(), temp2, NULL, w1->get_Y(), r, ctx);
    EC_POINT_add(w1->get_curve(), ciphertext->C1, temp1, temp2, ctx);
    // 计算C2 = r*H
    EC_POINT_mul(w1->get_curve(), ciphertext->C2, NULL, w1->get_H(), r, ctx);
    // 释放内存
    EC_POINT_free(temp1);
    EC_POINT_free(temp2);
    return ciphertext;
}

ElGamal_ciphertext *ElGamal_encrypt(W1 *w1, BIGNUM *plaintext, BN_CTX *ctx)
{
    // 生成随机数r
    BIGNUM *r = BN_new();
    BN_rand(r, 256, -1, 0);
    // 加密
    ElGamal_ciphertext *ciphertext = ElGamal_encrypt(w1, plaintext, r, ctx);
    BN_free(r);
    return ciphertext;
}

// 解密函数
EC_POINT *ElGamal_decrypt(W1 *w1, BIGNUM *sk, ElGamal_ciphertext *ciphertext, BN_CTX *ctx)
{
    // 计算 plaintext*Ga = C1 - (sk*C2)
    EC_POINT *plaintext_Ga = EC_POINT_new(w1->get_curve());
    EC_POINT *temp = EC_POINT_new(w1->get_curve());
    EC_POINT_mul(w1->get_curve(), temp, NULL, ciphertext->C2, sk, ctx);
    EC_POINT_sub(w1->get_curve(), plaintext_Ga, ciphertext->C1, temp, ctx);
    // 释放内存
    EC_POINT_free(temp);
    return plaintext_Ga;
}

int ElGamal_decrypt(W1 *w1, BIGNUM *sk_a, BIGNUM *sk_b, ElGamal_ciphertext *ciphertext, BN_CTX *ctx)
{
    // 计算 alpha = sk_a*C_2
    EC_POINT *alpha = EC_POINT_new(w1->get_curve());
    EC_POINT_mul(w1->get_curve(), alpha, NULL, ciphertext->C2, sk_a, ctx);
    // 计算 beta = sk_b*C_2
    EC_POINT *beta = EC_POINT_new(w1->get_curve());
    EC_POINT_mul(w1->get_curve(), beta, NULL, ciphertext->C2, sk_b, ctx);
    // 计算 plaintext*Ga = C1 - alpha - beta
    EC_POINT *plaintext_Ga = EC_POINT_new(w1->get_curve());
    EC_POINT *temp = EC_POINT_new(w1->get_curve());
    EC_POINT_add(w1->get_curve(), temp, alpha, beta, ctx);
    EC_POINT_sub(w1->get_curve(), plaintext_Ga, ciphertext->C1, temp, ctx);
    // 释放内存
    EC_POINT_free(alpha);
    EC_POINT_free(beta);
    EC_POINT_free(temp);
    if (EC_POINT_is_at_infinity(w1->get_curve(), plaintext_Ga))
        return 0;
    else
        return 1;
}