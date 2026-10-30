"""A small deny-list of very common passwords (lowercase). Teaching list, not a breach database."""

COMMON_PASSWORDS = frozenset(
    """
    password password1 password12 password123 passw0rd p@ssw0rd p@ssword 123456 1234567 12345678
    123456789 1234567890 12345678910 qwerty qwerty123 qwertyuiop qwerty12345 abc123 abc12345
    letmein welcome welcome1 welcome123 admin admin123 administrator iloveyou monkey dragon
    football baseball master login princess sunshine trustno1 111111 000000 123123 654321
    changeme default superman batman whatever freedom shadow michael jennifer 1q2w3e4r
    1qaz2wsx zaq12wsx asdfghjkl zxcvbnm passw0rd1 letmein123 secret secret123 test1234
    """.split()
)
