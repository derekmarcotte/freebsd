#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <crypt.h>
#include <unistd.h>
#include <stdio.h>

#include <atf-c.h>

#define	LEET "0.s0.l33t"

ATF_TC(md5);
ATF_TC_HEAD(md5, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests the MD5 based password hash");
}

ATF_TC_BODY(md5, tc)
{
	const char want[] = "$1$deadbeef$0Huu6KHrKLVWfqa4WljDE0";
	char *pw;

	pw = crypt(LEET, want);
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(md5invalid);
ATF_TC_HEAD(md5invalid, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests that md5invalid password fails");
}

ATF_TC_BODY(md5invalid, tc)
{
	const char want[] = "$1$cafebabe$0Huu6KHrKLVWfqa4WljDE0";
	char *pw;

	pw = crypt(LEET, want);
	ATF_CHECK(strcmp(pw, want) != 0);
}

ATF_TC(sha256_vector_1);
ATF_TC_HEAD(sha256_vector_1, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test vector from crypt-sha256.c");
}

ATF_TC_BODY(sha256_vector_1, tc)
{
	const char want[] = "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5";
	char *pw;

	pw = crypt("Hello world!", "$5$saltstring");
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(sha256_invalid);
ATF_TC_HEAD(sha256_invalid, tc)
{
	atf_tc_set_md_var(tc, "descr", "Tests that an invalid password fails");
}

ATF_TC_BODY(sha256_invalid, tc)
{
	const char want[] = "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5";
	char *pw;

	pw = crypt("Goodbye cruel world!", "$5$saltstring");
	ATF_CHECK(strcmp(pw, want) != 0);
}

ATF_TC(sha256_vector_2);
ATF_TC_HEAD(sha256_vector_2, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test vector from crypt-sha256.c");
}

ATF_TC_BODY(sha256_vector_2, tc)
{
	const char want[] = "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2."
		"opqey6IcA";
	char *pw;

	pw = crypt("Hello world!", "$5$rounds=10000$saltstringsaltstring");
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(sha256_vector_3);
ATF_TC_HEAD(sha256_vector_3, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test vector from crypt-sha256.c");
}

ATF_TC_BODY(sha256_vector_3, tc)
{
	const char want[] = "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8"
		"mGRcvxa5";
	char *pw;

	pw = crypt("This is just a test", "$5$rounds=5000$toolongsaltstring");
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(sha256_vector_4);
ATF_TC_HEAD(sha256_vector_4, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test vector from crypt-sha256.c");
}

ATF_TC_BODY(sha256_vector_4, tc)
{
	const char want[] = "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12"
		"oP84Bnq1";
	char *pw;

	pw = crypt("a very much longer text to encrypt.  This one even stretches over more"
		"than one line.", "$5$rounds=1400$anotherlongsaltstring");
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(sha256_vector_5);
ATF_TC_HEAD(sha256_vector_5, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test vector from crypt-sha256.c");
}

ATF_TC_BODY(sha256_vector_5, tc)
{
	const char want[] = "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/";
	char *pw;

	pw = crypt("we have a short salt string but not a short password", "$5$rounds=77777$short");
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(sha256_vector_6);
ATF_TC_HEAD(sha256_vector_6, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test vector from crypt-sha256.c");
}

ATF_TC_BODY(sha256_vector_6, tc)
{
	const char want[] = "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/"
		"cZKmF/wJvD";
	char *pw;

	pw = crypt("a short string", "$5$rounds=123456$asaltof16chars..");
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(sha256_vector_7);
ATF_TC_HEAD(sha256_vector_7, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test vector from crypt-sha256.c");
}

ATF_TC_BODY(sha256_vector_7, tc)
{
	const char want[] = "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL97"
		"2bIC";
	char *pw;

	pw = crypt("the minimum number is still observed", "$5$rounds=10$roundstoolow");
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(sha512_vector_1);
ATF_TC_HEAD(sha512_vector_1, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test vector from crypt-sha512.c");
}

ATF_TC_BODY(sha512_vector_1, tc)
{
	const char want[] = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu"
		"esI68u4OTLiBFdcbYEdFCoEOfaS35inz1";
	char *pw;

	pw = crypt("Hello world!", "$6$saltstring");
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(sha512_invalid);
ATF_TC_HEAD(sha512_invalid, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test vector from crypt-sha512.c");
}

ATF_TC_BODY(sha512_invalid, tc)
{
	const char want[] = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu"
		"esI68u4OTLiBFdcbYEdFCoEOfaS35inz1";
	char *pw;

	pw = crypt("Goodbye cruel world!", "$6$saltstring");
	ATF_CHECK(strcmp(pw, want) != 0);
}

ATF_TC(sha512_vector_2);
ATF_TC_HEAD(sha512_vector_2, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test vector from crypt-sha512.c");
}

ATF_TC_BODY(sha512_vector_2, tc)
{
	const char want[] = "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sb"
		"HbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.";
	char *pw;

	pw = crypt("Hello world!", "$6$rounds=10000$saltstringsaltstring");
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(sha512_vector_3);
ATF_TC_HEAD(sha512_vector_3, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test vector from crypt-sha512.c");
}

ATF_TC_BODY(sha512_vector_3, tc)
{
	const char want[] = "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQ"
		"zQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0";
	char *pw;

	pw = crypt("This is just a test", "$6$rounds=5000$toolongsaltstring");
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(sha512_vector_4);
ATF_TC_HEAD(sha512_vector_4, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test vector from crypt-sha512.c");
}

ATF_TC_BODY(sha512_vector_4, tc)
{
	const char want[] = "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wP"
		"vMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1";
	char *pw;

	pw = crypt("a very much longer text to encrypt.  This one even stretches over more"
		"than one line.", "$6$rounds=1400$anotherlongsaltstring");
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(sha512_vector_5);
ATF_TC_HEAD(sha512_vector_5, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test vector from crypt-sha512.c");
}

ATF_TC_BODY(sha512_vector_5, tc)
{
	const char want[] = "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0g"
		"ge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0";
	char *pw;

	pw = crypt("we have a short salt string but not a short password", "$6$rounds=77777$short");
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(sha512_vector_6);
ATF_TC_HEAD(sha512_vector_6, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test vector from crypt-sha512.c");
}

ATF_TC_BODY(sha512_vector_6, tc)
{
	const char want[] = "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc"
		"elCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1";
	char *pw;

	pw = crypt("a short string", "$6$rounds=123456$asaltof16chars..");
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(sha512_vector_7);
ATF_TC_HEAD(sha512_vector_7, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test vector from crypt-sha512.c");
}

ATF_TC_BODY(sha512_vector_7, tc)
{
	const char want[] = "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1x"
		"hLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.";
	char *pw;

	pw = crypt("the minimum number is still observed", "$6$rounds=10$roundstoolow");
	ATF_CHECK_STREQ(pw, want);
}

#ifdef HAS_BLOWFISH	
ATF_TC(blf_vector_1);
ATF_TC_HEAD(blf_vector_1, tc)
{
	atf_tc_set_md_var(tc, "descr", "Solar Designer wrapper.c test vector 1");
}

ATF_TC_BODY(blf_vector_1, tc)
{
	const char want[] = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
	char *pw;
	
	pw = crypt("U*U", want);
	ATF_CHECK_STREQ(pw, want);
}

	
ATF_TC(blf_invalid);
ATF_TC_HEAD(blf_invalid, tc)
{
	atf_tc_set_md_var(tc, "descr", "Solar Designer wrapper.c test vector 1 - invalid");
}

ATF_TC_BODY(blf_invalid, tc)
{
	const char want[] = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
	char *pw;
	
	pw = crypt("ME*ME", want);
	ATF_CHECK(strcmp(pw, want) != 0);
}

ATF_TC(blf_vector_2);
ATF_TC_HEAD(blf_vector_2, tc)
{
	atf_tc_set_md_var(tc, "descr", "Solar Designer wrapper.c test vector 2");
}

ATF_TC_BODY(blf_vector_2, tc)
{
	const char want[] = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK";
	char *pw;
	
	pw = crypt("U*U*", want);
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(blf_vector_3);
ATF_TC_HEAD(blf_vector_3, tc)
{
	atf_tc_set_md_var(tc, "descr", "Solar Designer wrapper.c test vector 3 - long password");
}

ATF_TC_BODY(blf_vector_3, tc)
{
	const char want[] = "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui";
	char *pw;
	
	pw = crypt("0123456789abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		"chars after 72 are ignored", want);
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(blf_vector_4);
ATF_TC_HEAD(blf_vector_4, tc)
{
	atf_tc_set_md_var(tc, "descr", "Solar Designer wrapper.c test vector 4");
}

ATF_TC_BODY(blf_vector_4, tc)
{
	const char want[] = "$2b$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e";
	char *pw;
	
	pw = crypt("\xff\xff\xa3", want);
	ATF_CHECK_STREQ(pw, want);
}

ATF_TC(blf_vector_5);
ATF_TC_HEAD(blf_vector_5, tc)
{
	atf_tc_set_md_var(tc, "descr", "Solar Designer wrapper.c test vector 5 - ensure our $2a$05$ matches the $2y$05$");
}

ATF_TC_BODY(blf_vector_5, tc)
{
	const char want[] = "$2a$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e";
	char *pw;
	
	pw = crypt("\xff\xa3" "345", want);
	ATF_CHECK_STREQ(pw, want);
}

#endif	

/*
 * This function must not do anything except enumerate
 * the test cases, per atf-c-api(3).
 */
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, md5);
	ATF_TP_ADD_TC(tp, md5invalid);
	
	ATF_TP_ADD_TC(tp, sha256_vector_1);
	ATF_TP_ADD_TC(tp, sha256_invalid);
	ATF_TP_ADD_TC(tp, sha256_vector_2);
	ATF_TP_ADD_TC(tp, sha256_vector_3);
	ATF_TP_ADD_TC(tp, sha256_vector_4);
/*
	ATF_TP_ADD_TC(tp, sha256_vector_5);
	ATF_TP_ADD_TC(tp, sha256_vector_6);
*/
	ATF_TP_ADD_TC(tp, sha256_vector_7);
	
	ATF_TP_ADD_TC(tp, sha512_vector_1);
	ATF_TP_ADD_TC(tp, sha512_invalid);
	ATF_TP_ADD_TC(tp, sha512_vector_2);
	ATF_TP_ADD_TC(tp, sha512_vector_3);
	ATF_TP_ADD_TC(tp, sha512_vector_4);
/*
	ATF_TP_ADD_TC(tp, sha512_vector_5);
	ATF_TP_ADD_TC(tp, sha512_vector_6);
*/
	ATF_TP_ADD_TC(tp, sha512_vector_7);

#ifdef HAS_BLOWFISH	
	ATF_TP_ADD_TC(tp, blf_vector_1);
	ATF_TP_ADD_TC(tp, blf_invalid);
	ATF_TP_ADD_TC(tp, blf_vector_2);
	ATF_TP_ADD_TC(tp, blf_vector_3);
	ATF_TP_ADD_TC(tp, blf_vector_4);
	ATF_TP_ADD_TC(tp, blf_vector_5);
#endif	

	return atf_no_error();
}
