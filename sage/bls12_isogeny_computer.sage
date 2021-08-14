# look for isogenous curves having j-invariant not in {0, 1728}
# Caution: this can take a while!
def find_iso(E):
    for p_test in primes(30):
        print("trying isogenies of degree %d"%p_test)
        isos = []
        for i in E.isogenies_prime_degree(p_test):            
            print("checking j-invariant of isogeny ", i)
            jinv = i.codomain().j_invariant()
            print("j-invariant is ", jinv)
            if jinv not in (0, 1728):
                isos.append(i)
                break
        
        if len(isos) > 0:
            print("found isogeny ", isos[0])
            return isos[0].dual()

    return None

def bls12_381_isos():
    # BLS12-381 parameters
    z = -0xd201000000010000
    h = (z - 1) ** 2 // 3
    q = z ** 4 - z ** 2 + 1
    p = z + h * q
    assert is_prime(p)
    assert is_prime(q)

    # E1
    F = GF(p)
    Ell = EllipticCurve(F, [0, 4])
    assert Ell.order() == h * q
    # E2
    F2.<X> = GF(p^2, modulus=[1,0,1])
    Ell2 = EllipticCurve(F2, [0, 4 * (1 + X)])
    assert Ell2.order() % q == 0

    iso_G1 = find_iso(Ell)
    # an isogeny from E’ to E,
    Ell_prime = iso_G1.domain()
    # where this is E’
    assert iso_G1(Ell_prime.random_point()).curve() == Ell
    iso_G2 = find_iso(Ell2)
    # an isogeny from E2’ to E2,
    Ell2_prime = iso_G2.domain()
    # where this is E2’
    assert iso_G2(Ell2_prime.random_point()).curve() == Ell2

def bls12_377_isos():
    p = 0x01ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001    # BLS12-377 parameters
    q = 0x12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a11800000000001
    z = 0x8508c00000000001
    #z = -0xd201000000010000
    h = (z - 1) ** 2 // 3
    q1 = z ** 4 - z ** 2 + 1
    p1 = z + h * q
    assert(q1 == q)
    assert(p1 == p)
    assert is_prime(p)
    assert is_prime(q)

    # E1
    F = GF(p)
    Ell = EllipticCurve(F, [0, 1])
    assert Ell.order() == h * q
    # E2
    quad_non_res = 0x01ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508bffffffffffc
    F.<X> = GF(p)[]
    F2.<X2> = GF(p^2, modulus=X^2 - quad_non_res)
    #F2.<X> = GF(p^2, modulus=[1,0,quad_non_res])
    B = 155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906 * X2
    Ell2 = EllipticCurve(F2, [0, B])
    assert Ell2.order() % q == 0

    F.<X> = GF(p)[]
    F6.<X6> = GF(p^6, modulus=X^6 - quad_non_res)
    B = 155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906 * X6^3
    Ell2_6 = EllipticCurve(F6, [0, B])
    Ell2_6.order() % q

    G1_X = 0x008848defe740a67c8fc6225bf87ff5485951e2caa9d41bb188282c8bd37cb5cd5481512ffcd394eeab9b16eb21be9ef
    G1_Y = 0x01914a69c5102eff1f674f5d30afeec4bd7fb348ca3e52d96d182ad44fb82305c2fe3d3634a9591afd82de55559c8ea6
    #make sure the generator is on the curve
    X_cx0 = 0x018480be71c785fec89630a2a3841d01c565f071203e50317ea501f557db6b9b71889f52bb53540274e3e48f7c005196
    X_cx1 = 0x00ea6040e700403170dc5a51b1b140d5532777ee6651cecbe7223ece0799c9de5cf89984bff76fe6b26bfefa6ea16afe
    Y_cy0 = 0x00690d665d446f7bd960736bcbb2efb4de03ed7274b49a58e458c282f832d204f2cf88886d8c7c2ef094094409fd4ddf
    Y_cy1 = 0x00f8169fd28355189e549da3151a70aa61ef11ac3d591bf12463b01acee304c24279b83f5e52270bd9a1cdd185eb8f93

    iso_G1 = find_iso(Ell)
    # an isogeny from E’ to E,
    Ell_prime = iso_G1.domain()
    # where this is E’
    assert iso_G1(Ell_prime.random_point()).curve() == Ell
    iso_G2 = find_iso(Ell2_6)
    # an isogeny from E2’ to E2,
    Ell2_prime = iso_G2.domain()
    # where this is E2’
    assert iso_G2(Ell2_prime.random_point()).curve() == Ell2_6
    return (iso_G1, iso_G2)

def trace_endo(P, p2):
    ParentCurve = P.curve()
    return P + ParentCurve((P[0]^p2, P[1]^p2)) + ParentCurve((P[0]^(p2^2), P[1]^(p2^2)))
    
def bls12_377_hash_to_G2(e2_p6S_iso, data):
    p = 0x01ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001    # BLS12-377 parameters
    Fp = GF(p)
    # E2
    quad_non_res = 0x01ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508bffffffffffc
    F.<X> = GF(p)[]
    F2.<X2> = GF(p^2, modulus=X^2 - quad_non_res)
    #F2.<X> = GF(p^2, modulus=[1,0,quad_non_res])
    B = 155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906 * X2
    Ell2 = EllipticCurve(F2, [0, B])

    F.<X> = GF(p)[]
    F6.<X6> = GF(p^6, modulus=X^6 - quad_non_res)
    B = 155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906 * X6^3
    Ell2_6 = EllipticCurve(F6, [0, B])

    Fpelm = Fp(hash(data))
            
    Ep2 = e2_p6S_iso.domain()
    a = Ep2.hyperelliptic_polynomials()[0][1]
    b = Ep2.hyperelliptic_polynomials()[0][0]
    
    X_0 = - (b/a) * ( 1 + 1/(xsi^2*Fpelm^4 + xsi*Fpelm^2))

    if Ep2.is_x_coord(X_0):
        P_p = Ep2.lift_x(X_0)
    else:
        P_p = Ep2.lift_x(xsi*Fpelm^2*X_0)

    P_F_6 = e2_p6S_iso(P_p)

    P = trace_endo(P_F_6, p^2)

    x_p = P[0].polynomial().coefficients()[1]*X2 + P[0].polynomial().coefficients()[0]
    y_p = P[1].polynomial().coefficients()[1]*X2 + P[1].polynomial().coefficients()[0]
    
    P_down = Ell2((x_p,y_p))

    return P_down
    
# BLS12-377 curve is fully defined by the following set of parameters (coefficient A=0 for all BLS12 curves):

# Base field modulus = 0x01ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001
# B coefficient = 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
# Main subgroup order = 0x12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a11800000000001
# Extension tower:
# Fp2 construction:
# Fp quadratic non-residue = 0x01ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508bffffffffffc
# Fp6/Fp12 construction:
# Fp2 cubic non-residue c0 = 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
# Fp2 cubic non-residue c1 = 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
# Twist parameters:
# Twist type: D
# B coefficient for twist c0 = 0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
# B coefficient for twist c1 = 0x010222f6db0fd6f343bd03737460c589dc7b4f91cd5fd889129207b63c6bf8000dd39e5c1ccccccd1c9ed9999999999a
# Generators:
# G1:
# X = 0x008848defe740a67c8fc6225bf87ff5485951e2caa9d41bb188282c8bd37cb5cd5481512ffcd394eeab9b16eb21be9ef
# Y = 0x01914a69c5102eff1f674f5d30afeec4bd7fb348ca3e52d96d182ad44fb82305c2fe3d3634a9591afd82de55559c8ea6
# G2:
# X cx0 = 0x018480be71c785fec89630a2a3841d01c565f071203e50317ea501f557db6b9b71889f52bb53540274e3e48f7c005196
# X cx1 = 0x00ea6040e700403170dc5a51b1b140d5532777ee6651cecbe7223ece0799c9de5cf89984bff76fe6b26bfefa6ea16afe
# Y cy0 = 0x00690d665d446f7bd960736bcbb2efb4de03ed7274b49a58e458c282f832d204f2cf88886d8c7c2ef094094409fd4ddf
# Y cy1 = 0x00f8169fd28355189e549da3151a70aa61ef11ac3d591bf12463b01acee304c24279b83f5e52270bd9a1cdd185eb8f93
# Pairing parameters:
# |x| (miller loop scalar) = 0x8508c00000000001
# x is negative = false

# Curve information:

# Base field: q = 258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177
# Scalar field: r = 8444461749428370424248824938781546531375899335154063827935233455917409239041
# valuation(q - 1, 2) = 46
# valuation(r - 1, 2) = 47
# G1 curve equation: y^2 = x^3 + 1
# G2 curve equation: y^2 = x^3 + B, where
# B = Fq2(0, 155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906)


# e26_order = Ell2_6.order()
# for i in primes(30):
#     if e26_order % i == 0:
#         print("order is divisable by ", i)

def find_non_square():
    quad_non_res = 0x01ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508bffffffffffc
    F.<X> = GF(p)[]
    F6.<X6> = GF(p^6, modulus=X^6 - quad_non_res)

    xsi = 0
    R.<X> = F6[]
    for i in F6:
        j = F6.random_element()
        if not j.is_square():
            xsi = j
            break

    return xsi

#xsi = find_non_square()
quad_non_res = 0x01ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508bffffffffffc
F.<X> = GF(p)[]
F6.<X6> = GF(p^6, modulus=X^6 - quad_non_res)
xsi = 219316876564715501445845678793720069854490678622108189766720284953606550746049804013989455416277727490975087855145*X6^5 + 189466179801738810887203415755624953151244475240588395433085007196132075694018697411282623497091853518199320679360*X6^4 + 108520825812509855860919714742321990242401369063484109910639742940603686352843166577300516208027451357460988981712*X6^3 + 34112775793303707113282524593132637468394825594735587392051797399858875786055772232469914619100641475357422803395*X6^2 + 24571511079604071320024029432159749780558012896103101565537728634741822079830191849836550641682167566004999041634*X6 + 159529377420408936856843219892213059773340895657856533814435812939320020966386099270143668590340681432634121813716

g1_iso, g2_iso = bls12_377_isos()
message = "'I refuse to prove that I exist,' says God, 'for proof denies faith, and without faith I am nothing.'"
print(bls12_377_hash_to_G2(g2_iso, message))
print(bls12_377_hash_to_G2(g2_iso, message))
message = "'if you stick a Babel fish in your ear you can instantly understand anything said to you in any form of language."
print(bls12_377_hash_to_G2(g2_iso, message))
print(bls12_377_hash_to_G2(g2_iso, message))
