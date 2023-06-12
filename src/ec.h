#pragma once
#include "base.h"

// 生成指定位数的随机BIGNUM
inline BIGNUM *BN_rand(int bits)
{
    BIGNUM *rand = BN_new();
    BN_rand(rand, bits, 0, 0);
    return rand;
}

// 将BIGNUM转换为十六进制字符串
inline std::string BN_to_string(BIGNUM *bn)
{
    char *tmp = BN_bn2hex(bn);
    std::string str(tmp);
    OPENSSL_free(tmp);
    return str;
}

// 将EC_POINT转换为十六进制字符串
inline std::string EC_POINT_to_string(EC_GROUP *curve, EC_POINT *point, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    char *tmp = EC_POINT_point2hex(curve, point, POINT_CONVERSION_COMPRESSED, ctx);
    std::string str(tmp);
    OPENSSL_free(tmp);
    BN_CTX_end(ctx);
    return str;
}

// 将BIGNUM转换为二进制字符串
inline std::string BN_serialize(BIGNUM *bn)
{
    std::string str;
    int len = BN_bn2mpi(bn, nullptr);
    str.resize(len);
    BN_bn2mpi(bn, (unsigned char *)str.data());
    return str;
}

// 将二进制字符串转换为BIGNUM
inline BIGNUM *BN_deserialize(std::string str)
{
    BIGNUM *bn = BN_mpi2bn((unsigned char *)str.data(), str.size(), nullptr);
    return bn;
}

// 将EC_POINT转换为二进制字符串
inline std::string EC_POINT_serialize(EC_GROUP *curve, EC_POINT *point, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    std::string str;
    int len = EC_POINT_point2oct(curve, point, POINT_CONVERSION_COMPRESSED, nullptr, 0, ctx);
    str.resize(len);
    EC_POINT_point2oct(curve, point, POINT_CONVERSION_COMPRESSED, (unsigned char *)str.data(), len, ctx);
    BN_CTX_end(ctx);
    return str;
}

// 将二进制字符串转换为EC_POINT
inline EC_POINT *EC_POINT_deserialize(EC_GROUP *curve, std::string str, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    EC_POINT *point = EC_POINT_new(curve);
    EC_POINT_oct2point(curve, point, (unsigned char *)str.data(), str.size(), ctx);
    BN_CTX_end(ctx);
    return point;
}

// 椭圆曲线点减法
void EC_POINT_sub(EC_GROUP *curve, EC_POINT *r, EC_POINT *a, EC_POINT *b, BN_CTX *ctx)
{
    EC_POINT *temp = EC_POINT_new(curve);
    EC_POINT_copy(temp, b);
    EC_POINT_invert(curve, temp, ctx);
    EC_POINT_add(curve, r, a, temp, ctx);
    EC_POINT_free(temp);
}

// 公开参数组W1
class W1
{
    EC_GROUP *curve;
    EC_POINT *G, *H, *Y;
    BIGNUM *order;

public:
    W1(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);

        // 选择曲线
        curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

        // 生成sk
        EC_KEY *key = EC_KEY_new();
        EC_KEY_set_group(key, curve);
        if (!EC_KEY_generate_key(key))
        {
            std::cerr << "Error generating key" << std::endl;
            return;
        }
        // 获取pk
        const EC_POINT *pk = EC_KEY_get0_public_key(key);

        // 获取order
        order = BN_new();
        EC_GROUP_get_order(curve, order, ctx);

        // 初始化 G0,G1,G2,H0,Ga,Ha,pkA
        G = EC_POINT_new(curve);
        H = EC_POINT_new(curve);
        Y = EC_POINT_new(curve);

        // 分别生成随机数计算G0,G1,G2,H0,Ga,Ha
        BIGNUM *r1 = BN_rand(256);
        BIGNUM *r2 = BN_rand(256);
        EC_POINT_mul(curve, G, NULL, pk, r1, ctx);
        EC_POINT_mul(curve, H, NULL, pk, r2, ctx);

        // Clean up
        BN_free(r1);
        BN_free(r2);
        EC_KEY_free(key);
        BN_CTX_end(ctx);
    }

    // 释放内存
    ~W1()
    {
        EC_POINT_free(G);
        EC_POINT_free(H);
        EC_POINT_free(Y);
        EC_GROUP_free(curve);
    }

    // 将W1的参数转换为字符串，并清理内存
    std::string to_string(BN_CTX *ctx)
    {
        BN_CTX_start(ctx);
        std::stringstream ss;
        char *tmp = EC_POINT_point2hex(curve, G, POINT_CONVERSION_COMPRESSED, ctx);
        ss << tmp;
        OPENSSL_free(tmp);
        tmp = EC_POINT_point2hex(curve, H, POINT_CONVERSION_COMPRESSED, ctx);
        ss << tmp;
        OPENSSL_free(tmp);
        tmp = EC_POINT_point2hex(curve, Y, POINT_CONVERSION_COMPRESSED, ctx);
        ss << tmp;
        OPENSSL_free(tmp);
        BN_CTX_end(ctx);
        return ss.str();
    }

    EC_GROUP *get_curve() const { return curve; }
    EC_POINT *get_G() const { return G; }
    EC_POINT *get_H() const { return H; }
    void set_Y(EC_POINT *Y) { EC_POINT_copy(this->Y, Y); }
    EC_POINT *get_Y() const { return Y; }
    BIGNUM *get_order() const { return order; }
};
