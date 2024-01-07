from Crypto.Util.number import long_to_bytes, bytes_to_long


def message_recover(prefix, sec_len, suffix, c, n, e):
    ZmodN = Zmod(n)
    P.<x> = PolynomialRing(ZmodN)
    suffix_len = len(suffix)
    a = ZmodN(
        (bytes_to_long(prefix) * (2 ^ ((sec_len + suffix_len) * 8)))
        + bytes_to_long(suffix)
    )
    b = ZmodN(Integer(2 ^ (suffix_len * 8)))
    c = ZmodN(c)
    f = (a + b * x) ^ e - c
    f = f.monic()
    roots = f.small_roots(epsilon=1 / 20)
    rc = len(roots)
    if rc == 0:
        return None
    elif rc == 1:
        message = a + b * (roots[0])
        return long_to_bytes(int(message))
    else:
        print(
            "Don't know how to handle situation when multiple roots are returned:", rc
        )
        sys.exit(1)


def encrypt(m, n, e):
    m = bytes_to_long(m)
    return pow(m, e, n)


def demo(
    n=None,
    bits=None,
    e=None,
    c=None,
    prefix=None,
    suffix=None,
    test_secret=None,
    secret_len=None,
):
    if "n" not in locals() or n is None:
        print("Generating public modulus..")
        if "bits" not in locals() or bits is None:
            bits = 4096
        pn = 2 ^ (bits // 2) - 1
        pl = 2 ^ (bits // 2 - 1)
        p = random_prime(pn, False, pl)
        q = random_prime(pn, False, pl)
        n = p * q
        print("n=", n)
    else:
        if not ("bits" not in locals() or bits is None):
            print(
                'Error: if you defined "n"', n, 'you should not specify "bits"!', bits
            )
            sys.exit(1)

    if "e" not in locals() or e is None:
        e = 5
        print("e=", e)

    if "suffix" not in locals() or suffix is None:
        suffix = (
            bytearray([0x0A])
            + "The quick brown fox jumped over ??".encode()
            + bytearray([0x0A])
        )

    if "prefix" not in locals() or prefix is None:
        prefix = "Alice was beginning to get very tired of sitting by her sister on the bank, and of having nothing to do once or twice she had peeped into sister was reading, but it had no pictures or conversations in it, and what is the use of a book thought Alice without".encode() + bytearray(
            [0xE8, 0x01]
        )

    if "c" not in locals() or c is None:
        if "test_secret" not in locals() or test_secret is None:
            if "secret_len" not in locals() or secret_len is None:
                secret_len = 51
            test_secret = (bytearray([0xFF])) * int(
                secret_len
            )  # You can also fill this with pseudorandom bytes rather than fixed bytes
        else:
            secret_len = len(test_secret)

        plaintext = prefix + test_secret + suffix
        c = encrypt(plaintext, n, e)
        print("c=", c)
    else:
        if "secret_len" not in locals() or secret_len is None:
            secret_len = 51

    e = Integer(e)
    n = Integer(n)
    c = Integer(c)
    max_secret_len = max(n.nbits(), c.nbits()) // 8 - len(prefix) - len(suffix)
    if secret_len > max_secret_len:
        print(
            "Error: The secret length of",
            secret_len,
            "byte(s) is larger then the maximum of",
            max_secret_len,
            "bytes(s) for the given prefix, suffix, encrypted message and the public exponent!",
        )
        sys.exit(1)

    print(
        "Will recover the secret with the length of up to a maximum",
        max_secret_len,
        "byte(s).",
    )

    # Attack
    while True:
        print("Trying to recover the message", secret_len, "byte(s) long...")
        message = message_recover(prefix, secret_len, suffix, c, n, e)
        if message is not None:
            # Uncomment the following if you need to write decrypted message on disk
            #            with open("decrypted-message.bin", "wb") as file:
            #                file.write(message)
            #                file.close()
            break
        else:
            if secret_len > max_secret_len:
                print("Could not recover the message, sorry!")
                sys.exit(1)
        secret_len += 1

    # Result
    print("Decrypted message:", message)
    if ("plaintext" in locals()) and (plaintext is not None) and (plaintext != message):
        print("Original message:", plaintext)

def test():
    demo(
        prefix='KCSC{'.encode(),
        suffix="3y3s_0f_LLL}".encode(),
        secret_len=13,
        n = 805467500635696403604126524373650578882729068725582344971555936471728279008969317394226798274039587275908735628164913963756789131471531490012281262137708844664619411648776174742900969650281132608104486439462068493207388096754400356209191212924158917441463852311090597438686723680422989566039830705971272945580630621308622704812919416445637277433384864510484266136345300166188170847768250622904194100556098235897898548354386415341541887443486684297114240486341073977172459860420916964212739802004276614553755113124726331629822694410052832980560107812738167277181748569891715410067156205497753620739994002924247168259596220654379789860120944816884358006621854492232604827642867109476922149510767118658715534476782931763110787389666428593557178061972898056782926023179701767472969849999844288795597293792471883445525249025377326859655523448211020675915933552601140243332965620235850177872856558184848182439374292376522160931072677877590262080551636962148104050583711183119856867201924407132152091888936970437318064654447142605921825771487108398034919404885812834444299826080204996660391375038388918601615609593999711720104533648851576138805705999947802739408729788376315233147532770988216608571607302006681600662261521288802804512781133,
        e = 5,
        c = 37818324773754623690662481523875731969084411166141554357091068170570851867792688671578055848365488514038670055641355805895456464026501608283532786478121405125354617413182592066592955398639993437391595614785597437530326001585537002012683789925088343055381162945637571558616108450400551207378717421673195548161119063365955434406551060744590878738884866538571149,
    )
if __name__ == "__main__":
    test()