package chacha20poly1305_test

import (
	"encoding/hex"
	"strings"
)

func str2bs(str ...string) []byte {
	bs := []byte{}
	for _, s := range str {
		tmp, _ := hex.DecodeString(strings.Replace(s, " ", "", -1))
		bs = append(bs, tmp...)
	}
	return bs
}

type A1 struct {
	Key       []byte
	Nonce     []byte
	Counter   uint32
	Keystream []byte
}

func getTestVectorsA1() []A1 {
	// A.1.  The ChaCha20 Block Functions
	tvs := []A1{}
	//   Test Vector #1:
	//   ==============
	tv1 := A1{}
	//   Key:
	//   000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	//   016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	tv1.Key = str2bs(
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	//   Nonce:
	//   000  00 00 00 00 00 00 00 00 00 00 00 00              ............
	tv1.Nonce = str2bs("00 00 00 00 00 00 00 00 00 00 00 00")
	//   Block Counter = 0
	tv1.Counter = uint32(0)
	//     ChaCha state at the end
	//         ade0b876  903df1a0  e56a5d40  28bd8653
	//         b819d2bd  1aed8da0  ccef36a8  c70d778b
	//         7c5941da  8d485751  3fe02477  374ad8b8
	//         f4b8436a  1ca11815  69b687c3  8665eeb2

	//   Keystream:
	//   000  76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28  v.....=.@]j.S..(
	//   016  bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7  .........6...w..
	//   032  da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37  .AY|QWH.w$.?..J7
	//   048  6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86  jC.........i..e.
	tv1.Keystream = str2bs(
		"76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28",
		"bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7",
		"da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37",
		"6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86",
	)
	tvs = append(tvs, tv1)

	// Test Vector #2:
	// ==============
	tv2 := A1{}
	// Key:
	// 000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	// 016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	tv2.Key = str2bs(
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	// Nonce:
	// 000  00 00 00 00 00 00 00 00 00 00 00 00              ............
	tv2.Nonce = str2bs("00 00 00 00 00 00 00 00 00 00 00 00")
	// Block Counter = 1
	tv2.Counter = uint32(1)
	//   ChaCha state at the end
	//       bee7079f  7a385155  7c97ba98  0d082d73
	//       a0290fcb  6965e348  3e53c612  ed7aee32
	//       7621b729  434ee69c  b03371d5  d539d874
	//       281fed31  45fb0a51  1f0ae1ac  6f4d794b

	// Keystream:
	// 000  9f 07 e7 be 55 51 38 7a 98 ba 97 7c 73 2d 08 0d  ....UQ8z...|s-..
	// 016  cb 0f 29 a0 48 e3 65 69 12 c6 53 3e 32 ee 7a ed  ..).H.ei..S>2.z.
	// 032  29 b7 21 76 9c e6 4e 43 d5 71 33 b0 74 d8 39 d5  ).!v..NC.q3.t.9.
	// 048  31 ed 1f 28 51 0a fb 45 ac e1 0a 1f 4b 79 4d 6f  1..(Q..E....KyMo
	tv2.Keystream = str2bs(
		"9f 07 e7 be 55 51 38 7a 98 ba 97 7c 73 2d 08 0d",
		"cb 0f 29 a0 48 e3 65 69 12 c6 53 3e 32 ee 7a ed",
		"29 b7 21 76 9c e6 4e 43 d5 71 33 b0 74 d8 39 d5",
		"31 ed 1f 28 51 0a fb 45 ac e1 0a 1f 4b 79 4d 6f",
	)
	tvs = append(tvs, tv2)

	// Test Vector #3:
	// ==============
	tv3 := A1{}
	// Key:
	// 000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	// 016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01  ................
	tv3.Key = str2bs(
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01",
	)
	// Nonce:
	// 000  00 00 00 00 00 00 00 00 00 00 00 00              ............
	tv3.Nonce = str2bs("00 00 00 00 00 00 00 00 00 00 00 00")
	// Block Counter = 1
	tv3.Counter = uint32(1)
	//   ChaCha state at the end
	//       2452eb3a  9249f8ec  8d829d9b  ddd4ceb1
	//       e8252083  60818b01  f38422b8  5aaa49c9
	//       bb00ca8e  da3ba7b4  c4b592d1  fdf2732f
	//       4436274e  2561b3c8  ebdd4aa6  a0136c00

	// Keystream:
	// 000  3a eb 52 24 ec f8 49 92 9b 9d 82 8d b1 ce d4 dd  :.R$..I.........
	// 016  83 20 25 e8 01 8b 81 60 b8 22 84 f3 c9 49 aa 5a  . %....`."...I.Z
	// 032  8e ca 00 bb b4 a7 3b da d1 92 b5 c4 2f 73 f2 fd  ......;...../s..
	// 048  4e 27 36 44 c8 b3 61 25 a6 4a dd eb 00 6c 13 a0  N'6D..a%.J...l..
	tv3.Keystream = str2bs(
		"3a eb 52 24 ec f8 49 92 9b 9d 82 8d b1 ce d4 dd",
		"83 20 25 e8 01 8b 81 60 b8 22 84 f3 c9 49 aa 5a",
		"8e ca 00 bb b4 a7 3b da d1 92 b5 c4 2f 73 f2 fd",
		"4e 27 36 44 c8 b3 61 25 a6 4a dd eb 00 6c 13 a0",
	)
	tvs = append(tvs, tv3)

	// Test Vector #4:
	// ==============
	tv4 := A1{}
	// Key:
	// 000  00 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	// 016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	tv4.Key = str2bs(
		"00 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	// Nonce:
	// 000  00 00 00 00 00 00 00 00 00 00 00 00              ............
	tv4.Nonce = str2bs("00 00 00 00 00 00 00 00 00 00 00 00")
	// Block Counter = 2
	tv4.Counter = uint32(2)
	//   ChaCha state at the end
	//       fb4dd572  4bc42ef1  df922636  327f1394
	//       a78dea8f  5e269039  a1bebbc1  caf09aae
	//       a25ab213  48a6b46c  1b9d9bcb  092c5be6
	//       546ca624  1bec45d5  87f47473  96f0992e

	// Keystream:
	// 000  72 d5 4d fb f1 2e c4 4b 36 26 92 df 94 13 7f 32  r.M....K6&.....2
	// 016  8f ea 8d a7 39 90 26 5e c1 bb be a1 ae 9a f0 ca  ....9.&^........
	// 032  13 b2 5a a2 6c b4 a6 48 cb 9b 9d 1b e6 5b 2c 09  ..Z.l..H.....[,.
	// 048  24 a6 6c 54 d5 45 ec 1b 73 74 f4 87 2e 99 f0 96  $.lT.E..st......
	tv4.Keystream = str2bs(
		"72 d5 4d fb f1 2e c4 4b 36 26 92 df 94 13 7f 32",
		"8f ea 8d a7 39 90 26 5e c1 bb be a1 ae 9a f0 ca",
		"13 b2 5a a2 6c b4 a6 48 cb 9b 9d 1b e6 5b 2c 09",
		"24 a6 6c 54 d5 45 ec 1b 73 74 f4 87 2e 99 f0 96",
	)
	tvs = append(tvs, tv4)

	// Test Vector #5:
	// ==============
	tv5 := A1{}
	// Key:
	// 000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	// 016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	tv5.Key = str2bs(
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	// Nonce:
	// 000  00 00 00 00 00 00 00 00 00 00 00 02              ............
	tv5.Nonce = str2bs("00 00 00 00 00 00 00 00 00 00 00 02")
	// Block Counter = 0
	tv5.Counter = uint32(0)
	//   ChaCha state at the end
	//       374dc6c2  3736d58c  b904e24a  cd3f93ef
	//       88228b1a  96a4dfb3  5b76ab72  c727ee54
	//       0e0e978a  f3145c95  1b748ea8  f786c297
	//       99c28f5f  628314e8  398a19fa  6ded1b53

	// Keystream:
	// 000  c2 c6 4d 37 8c d5 36 37 4a e2 04 b9 ef 93 3f cd  ..M7..67J.....?.
	// 016  1a 8b 22 88 b3 df a4 96 72 ab 76 5b 54 ee 27 c7  ..".....r.v[T.'.
	// 032  8a 97 0e 0e 95 5c 14 f3 a8 8e 74 1b 97 c2 86 f7  .....\....t.....
	// 048  5f 8f c2 99 e8 14 83 62 fa 19 8a 39 53 1b ed 6d  _......b...9S..m
	tv5.Keystream = str2bs(
		"c2 c6 4d 37 8c d5 36 37 4a e2 04 b9 ef 93 3f cd",
		"1a 8b 22 88 b3 df a4 96 72 ab 76 5b 54 ee 27 c7",
		"8a 97 0e 0e 95 5c 14 f3 a8 8e 74 1b 97 c2 86 f7",
		"5f 8f c2 99 e8 14 83 62 fa 19 8a 39 53 1b ed 6d",
	)
	tvs = append(tvs, tv5)
	return tvs
}

type A2 struct {
	Key        []byte
	Nonce      []byte
	Counter    uint32
	Plaintext  []byte
	Ciphertext []byte
}

func getTestVectorsA2() []A2 {
	tvs := []A2{}
	// A.2.  ChaCha20 Encryption

	// Test Vector #1:
	// ==============
	tv1 := A2{}
	// Key:
	// 000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	// 016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	tv1.Key = str2bs(
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	// Nonce:
	// 000  00 00 00 00 00 00 00 00 00 00 00 00              ............
	tv1.Nonce = str2bs("00 00 00 00 00 00 00 00 00 00 00 00")
	// Initial Block Counter = 0
	tv1.Counter = uint32(0)
	// Plaintext:
	// 000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	// 016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	// 032  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	// 048  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	tv1.Plaintext = str2bs(
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	// Ciphertext:
	// 000  76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28  v.....=.@]j.S..(
	// 016  bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7  .........6...w..
	// 032  da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37  .AY|QWH.w$.?..J7
	// 048  6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86  jC.........i..e.
	tv1.Ciphertext = str2bs(
		"76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28",
		"bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7",
		"da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37",
		"6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86",
	)
	tvs = append(tvs, tv1)

	// Test Vector #2:
	// ==============
	tv2 := A2{}
	// Key:
	// 000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	// 016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01  ................
	tv2.Key = str2bs(
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01",
	)
	// Nonce:
	// 000  00 00 00 00 00 00 00 00 00 00 00 02              ............
	tv2.Nonce = str2bs("00 00 00 00 00 00 00 00 00 00 00 02")
	// Initial Block Counter = 1
	tv2.Counter = uint32(1)
	// Plaintext:
	// 000  41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74  Any submission t
	// 016  6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e  o the IETF inten
	// 032  64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72  ded by the Contr
	// 048  69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69  ibutor for publi
	// 064  63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72  cation as all or
	// 080  20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46   part of an IETF
	// 096  20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20   Internet-Draft
	// 112  6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73  or RFC and any s
	// 128  74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69  tatement made wi
	// 144  74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74  thin the context
	// 160  20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69   of an IETF acti
	// 176  76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72  vity is consider
	// 192  65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74  ed an "IETF Cont
	// 208  72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20  ribution". Such
	// 224  73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75  statements inclu
	// 240  64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e  de oral statemen
	// 256  74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69  ts in IETF sessi
	// 272  6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20  ons, as well as
	// 288  77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63  written and elec
	// 304  74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61  tronic communica
	// 320  74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e  tions made at an
	// 336  79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c  y time or place,
	// 352  20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65   which are addre
	// 368  73 73 65 64 20 74 6f                             ssed to
	tv2.Plaintext = str2bs(
		"41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74",
		"6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e",
		"64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72",
		"69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69",
		"63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72",
		"20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46",
		"20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20",
		"6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73",
		"74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69",
		"74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74",
		"20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69",
		"76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72",
		"65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74",
		"72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20",
		"73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75",
		"64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e",
		"74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69",
		"6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20",
		"77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63",
		"74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61",
		"74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e",
		"79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c",
		"20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65",
		"73 73 65 64 20 74 6f",
	)
	// Ciphertext:
	// 000  a3 fb f0 7d f3 fa 2f de 4f 37 6c a2 3e 82 73 70  ...}../.O7l.>.sp
	// 016  41 60 5d 9f 4f 4f 57 bd 8c ff 2c 1d 4b 79 55 ec  A`].OOW...,.KyU.
	// 032  2a 97 94 8b d3 72 29 15 c8 f3 d3 37 f7 d3 70 05  *....r)....7..p.
	// 048  0e 9e 96 d6 47 b7 c3 9f 56 e0 31 ca 5e b6 25 0d  ....G...V.1.^.%.
	// 064  40 42 e0 27 85 ec ec fa 4b 4b b5 e8 ea d0 44 0e  @B.'....KK....D.
	// 080  20 b6 e8 db 09 d8 81 a7 c6 13 2f 42 0e 52 79 50   ........./B.RyP
	// 096  42 bd fa 77 73 d8 a9 05 14 47 b3 29 1c e1 41 1c  B..ws....G.)..A.
	// 112  68 04 65 55 2a a6 c4 05 b7 76 4d 5e 87 be a8 5a  h.eU*....vM^...Z
	// 128  d0 0f 84 49 ed 8f 72 d0 d6 62 ab 05 26 91 ca 66  ...I..r..b..&..f
	// 144  42 4b c8 6d 2d f8 0e a4 1f 43 ab f9 37 d3 25 9d  BK.m-....C..7.%.
	// 160  c4 b2 d0 df b4 8a 6c 91 39 dd d7 f7 69 66 e9 28  ......l.9...if.(
	// 176  e6 35 55 3b a7 6c 5c 87 9d 7b 35 d4 9e b2 e6 2b  .5U;.l\..{5....+
	// 192  08 71 cd ac 63 89 39 e2 5e 8a 1e 0e f9 d5 28 0f  .q..c.9.^.....(.
	// 208  a8 ca 32 8b 35 1c 3c 76 59 89 cb cf 3d aa 8b 6c  ..2.5.<vY...=..l
	// 224  cc 3a af 9f 39 79 c9 2b 37 20 fc 88 dc 95 ed 84  .:..9y.+7 ......
	// 240  a1 be 05 9c 64 99 b9 fd a2 36 e7 e8 18 b0 4b 0b  ....d....6....K.
	// 256  c3 9c 1e 87 6b 19 3b fe 55 69 75 3f 88 12 8c c0  ....k.;.Uiu?....
	// 272  8a aa 9b 63 d1 a1 6f 80 ef 25 54 d7 18 9c 41 1f  ...c..o..%T...A.
	// 288  58 69 ca 52 c5 b8 3f a3 6f f2 16 b9 c1 d3 00 62  Xi.R..?.o......b
	// 304  be bc fd 2d c5 bc e0 91 19 34 fd a7 9a 86 f6 e6  ...-.....4......
	// 320  98 ce d7 59 c3 ff 9b 64 77 33 8f 3d a4 f9 cd 85  ...Y...dw3.=....
	// 336  14 ea 99 82 cc af b3 41 b2 38 4d d9 02 f3 d1 ab  .......A.8M.....
	// 352  7a c6 1d d2 9c 6f 21 ba 5b 86 2f 37 30 e3 7c fd  z....o!.[./70.|.
	// 368  c4 fd 80 6c 22 f2 21                             ...l".!
	tv2.Ciphertext = str2bs(
		"a3 fb f0 7d f3 fa 2f de 4f 37 6c a2 3e 82 73 70",
		"41 60 5d 9f 4f 4f 57 bd 8c ff 2c 1d 4b 79 55 ec",
		"2a 97 94 8b d3 72 29 15 c8 f3 d3 37 f7 d3 70 05",
		"0e 9e 96 d6 47 b7 c3 9f 56 e0 31 ca 5e b6 25 0d",
		"40 42 e0 27 85 ec ec fa 4b 4b b5 e8 ea d0 44 0e",
		"20 b6 e8 db 09 d8 81 a7 c6 13 2f 42 0e 52 79 50",
		"42 bd fa 77 73 d8 a9 05 14 47 b3 29 1c e1 41 1c",
		"68 04 65 55 2a a6 c4 05 b7 76 4d 5e 87 be a8 5a",
		"d0 0f 84 49 ed 8f 72 d0 d6 62 ab 05 26 91 ca 66",
		"42 4b c8 6d 2d f8 0e a4 1f 43 ab f9 37 d3 25 9d",
		"c4 b2 d0 df b4 8a 6c 91 39 dd d7 f7 69 66 e9 28",
		"e6 35 55 3b a7 6c 5c 87 9d 7b 35 d4 9e b2 e6 2b",
		"08 71 cd ac 63 89 39 e2 5e 8a 1e 0e f9 d5 28 0f",
		"a8 ca 32 8b 35 1c 3c 76 59 89 cb cf 3d aa 8b 6c",
		"cc 3a af 9f 39 79 c9 2b 37 20 fc 88 dc 95 ed 84",
		"a1 be 05 9c 64 99 b9 fd a2 36 e7 e8 18 b0 4b 0b",
		"c3 9c 1e 87 6b 19 3b fe 55 69 75 3f 88 12 8c c0",
		"8a aa 9b 63 d1 a1 6f 80 ef 25 54 d7 18 9c 41 1f",
		"58 69 ca 52 c5 b8 3f a3 6f f2 16 b9 c1 d3 00 62",
		"be bc fd 2d c5 bc e0 91 19 34 fd a7 9a 86 f6 e6",
		"98 ce d7 59 c3 ff 9b 64 77 33 8f 3d a4 f9 cd 85",
		"14 ea 99 82 cc af b3 41 b2 38 4d d9 02 f3 d1 ab",
		"7a c6 1d d2 9c 6f 21 ba 5b 86 2f 37 30 e3 7c fd",
		"c4 fd 80 6c 22 f2 21",
	)
	tvs = append(tvs, tv2)
	// Test Vector #3:
	// ==============
	tv3 := A2{}
	// Key:
	// 000  1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0  ..@..U...3......
	// 016  47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0  G9..@+....\. pu.
	tv3.Key = str2bs(
		"1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0",
		"47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0",
	)
	// Nonce:
	// 000  00 00 00 00 00 00 00 00 00 00 00 02              ............
	tv3.Nonce = str2bs("00 00 00 00 00 00 00 00 00 00 00 02")
	// Initial Block Counter = 42
	tv3.Counter = uint32(42)
	// Plaintext:
	// 000  27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61  'Twas brillig, a
	// 016  6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f  nd the slithy to
	// 032  76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64  ves.Did gyre and
	// 048  20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77   gimble in the w
	// 064  61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77  abe:.All mimsy w
	// 080  65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65  ere the borogove
	// 096  73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20  s,.And the mome
	// 112  72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e     raths outgrabe.
	tv3.Plaintext = str2bs(
		"27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61",
		"6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f",
		"76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64",
		"20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77",
		"61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77",
		"65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65",
		"73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20",
		"72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e",
	)
	// Ciphertext:
	// 000  62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df  b.4....._..Bo'..
	// 016  5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf  _....L.s....[...
	// 032  16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71  .m=..!...._.Lahq
	// 048  fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb  ...O.e...l....S.
	// 064  f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6  ..d.."4.*5k>vC..
	// 080  1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77  .U2.W....%h.}??w
	// 096  04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1  .......MP..Km.1.
	// 112  87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1     ....r..6uzyz...
	tv3.Ciphertext = str2bs(
		"62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df",
		"5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf",
		"16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71",
		"fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb",
		"f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6",
		"1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77",
		"04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1",
		"87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1",
	)
	tvs = append(tvs, tv3)
	return tvs
}

type A3 struct {
	Key []byte
	MAC []byte
	Tag []byte
}

func getTestVectorsA3() []A3 {
	tvs := []A3{}

	// Test Vector #1:
	// ==============
	tv1 := A3{}
	// One-time Poly1305 Key:
	// 000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	// 016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	tv1.Key = str2bs(
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	// Text to MAC:
	// 000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	// 016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	// 032  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	// 048  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	tv1.MAC = str2bs(
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	// Tag:
	// 000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	tv1.Tag = str2bs("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
	tvs = append(tvs, tv1)
	// Test Vector #2:
	// ==============
	tv2 := A3{}
	// One-time Poly1305 Key:
	// 000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	// 016  36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e  6.....`p...."z.>
	tv2.Key = str2bs(
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e",
	)
	// Text to MAC:
	// 000  41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74  Any submission t
	// 016  6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e  o the IETF inten
	// 032  64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72  ded by the Contr
	// 048  69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69  ibutor for publi
	// 064  63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72  cation as all or
	// 080  20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46   part of an IETF
	// 096  20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20   Internet-Draft
	// 112  6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73  or RFC and any s
	// 128  74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69  tatement made wi
	// 144  74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74  thin the context
	// 160  20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69   of an IETF acti
	// 176  76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72  vity is consider
	// 192  65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74  ed an "IETF Cont
	// 208  72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20  ribution". Such
	// 224  73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75  statements inclu
	// 240  64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e  de oral statemen
	// 256  74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69  ts in IETF sessi
	// 272  6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20  ons, as well as
	// 288  77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63  written and elec
	// 304  74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61  tronic communica
	// 320  74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e  tions made at an
	// 336  79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c  y time or place,
	// 352  20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65   which are addre
	// 368  73 73 65 64 20 74 6f                             ssed to
	tv2.MAC = str2bs(
		"41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74",
		"6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e",
		"64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72",
		"69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69",
		"63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72",
		"20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46",
		"20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20",
		"6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73",
		"74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69",
		"74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74",
		"20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69",
		"76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72",
		"65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74",
		"72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20",
		"73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75",
		"64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e",
		"74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69",
		"6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20",
		"77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63",
		"74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61",
		"74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e",
		"79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c",
		"20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65",
		"73 73 65 64 20 74 6f                           ",
	)
	// Tag:
	// 000  36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e  6.....`p...."z.>
	tv2.Tag = str2bs("36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e")
	tvs = append(tvs, tv2)
	// Test Vector #3:
	// ==============
	tv3 := A3{}
	// One-time Poly1305 Key:
	// 000  36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e  6.....`p...."z.>
	// 016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	tv3.Key = str2bs(
		"36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	// Text to MAC:
	// 000  41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74  Any submission t
	// 016  6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e  o the IETF inten
	// 032  64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72  ded by the Contr
	// 048  69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69  ibutor for publi
	// 064  63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72  cation as all or
	// 080  20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46   part of an IETF
	// 096  20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20   Internet-Draft
	// 112  6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73  or RFC and any s
	// 128  74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69  tatement made wi
	// 144  74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74  thin the context
	// 160  20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69   of an IETF acti
	// 176  76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72  vity is consider
	// 192  65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74  ed an "IETF Cont
	// 208  72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20  ribution". Such
	// 224  73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75  statements inclu
	// 240  64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e  de oral statemen
	// 256  74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69  ts in IETF sessi
	// 272  6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20  ons, as well as
	// 288  77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63  written and elec
	// 304  74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61  tronic communica
	// 320  74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e  tions made at an
	// 336  79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c  y time or place,
	// 352  20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65   which are addre
	// 368  73 73 65 64 20 74 6f                             ssed to
	tv3.MAC = str2bs(
		"41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74",
		"6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e",
		"64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72",
		"69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69",
		"63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72",
		"20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46",
		"20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20",
		"6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73",
		"74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69",
		"74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74",
		"20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69",
		"76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72",
		"65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74",
		"72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20",
		"73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75",
		"64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e",
		"74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69",
		"6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20",
		"77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63",
		"74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61",
		"74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e",
		"79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c",
		"20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65",
		"73 73 65 64 20 74 6f                           ",
	)
	// Tag:
	// 000  f3 47 7e 7c d9 54 17 af 89 a6 b8 79 4c 31 0c f0  .G~|.T.....yL1..
	tv3.Tag = str2bs("f3 47 7e 7c d9 54 17 af 89 a6 b8 79 4c 31 0c f0")
	tvs = append(tvs, tv3)
	// Test Vector #4:
	// ==============
	tv4 := A3{}
	// One-time Poly1305 Key:
	// 000  1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0  ..@..U...3......
	// 016  47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0  G9..@+....\. pu.
	tv4.Key = str2bs(
		"1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0",
		"47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0",
	)
	// Text to MAC:
	// 000  27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61  'Twas brillig, a
	// 016  6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f  nd the slithy to
	// 032  76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64  ves.Did gyre and
	// 048  20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77   gimble in the w
	// 064  61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77  abe:.All mimsy w
	// 080  65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65  ere the borogove
	// 096  73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20  s,.And the mome
	// 112  72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e     raths outgrabe.
	tv4.MAC = str2bs(
		"27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61",
		"6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f",
		"76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64",
		"20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77",
		"61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77",
		"65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65",
		"73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20",
		"72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e",
	)
	// Tag:
	// 000  45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62  EAf.~..a...|...b
	tv4.Tag = str2bs("45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62")
	tvs = append(tvs, tv4)

	// 	Test Vector #5: If one uses 130-bit partial reduction, does the code handle the case where partially reduced final result is not fully reduced?

	//    R:
	//    02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	//    S:
	//    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	tv5 := A3{}
	tv5.Key = str2bs(
		"02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	//    data:
	//    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
	tv5.MAC = str2bs("FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF")
	//    tag:
	//    03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	tv5.Tag = str2bs("03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
	tvs = append(tvs, tv5)

	//    Test Vector #6: What happens if addition of s overflows modulo 2^128?

	//    R:
	//    02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	//    S:
	//    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
	tv6 := A3{}
	tv6.Key = str2bs(
		"02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",
	)
	//    data:
	//    02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	tv6.MAC = str2bs("02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
	//    tag:
	//    03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	tv6.Tag = str2bs("03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
	tvs = append(tvs, tv6)
	// Test Vector #7: What happens if data limb is all ones and there is
	// carry from lower limb?

	// R:
	// 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	// S:
	// 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	tv7 := A3{}
	tv7.Key = str2bs(
		"01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	// data:
	// FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
	// F0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
	// 11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	tv7.MAC = str2bs(
		"FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",
		"F0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",
		"11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	// tag:
	// 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	tv7.Tag = str2bs("05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
	tvs = append(tvs, tv7)

	// Test Vector #8: What happens if final result from polynomial part is
	// exactly 2^130-5?

	// R:
	// 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	// S:
	// 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	tv8 := A3{}
	tv8.Key = str2bs(
		"01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	// data:
	// FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
	// FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE
	// 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
	tv8.MAC = str2bs(
		"FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",
		"FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE",
		"01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01",
	)
	// tag:
	// 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	tv8.Tag = str2bs("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
	tvs = append(tvs, tv8)

	// Test Vector #9: What happens if final result from polynomial part is
	// exactly 2^130-6?

	// R:
	// 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	// S:
	// 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	tv9 := A3{}
	tv9.Key = str2bs(
		"02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	// data:
	// FD FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
	tv9.MAC = str2bs(
		"FD FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF",
	)
	// tag:
	// FA FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
	tv9.Tag = str2bs("FA FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF")
	tvs = append(tvs, tv9)

	// Test Vector #10: What happens if 5*H+L-type reduction produces
	// 131-bit intermediate result?

	// R:
	// 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00
	// S:
	// 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	tv10 := A3{}
	tv10.Key = str2bs(
		"01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	// data:
	// E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
	// 33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
	// 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	// 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	tv10.MAC = str2bs(
		"E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00",
		"33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	// tag:
	// 14 00 00 00 00 00 00 00 55 00 00 00 00 00 00 00
	tv10.Tag = str2bs("14 00 00 00 00 00 00 00 55 00 00 00 00 00 00 00")
	tvs = append(tvs, tv10)

	// Test Vector #11: What happens if 5*H+L-type reduction produces
	// 131-bit final result?

	// R:
	// 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00
	// S:
	// 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	tv11 := A3{}
	tv11.Key = str2bs(
		"01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	// data:
	// E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
	// 33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
	// 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	tv11.MAC = str2bs(
		"E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00",
		"33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	// tag:
	// 13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	tv11.Tag = str2bs("13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
	tvs = append(tvs, tv11)

	return tvs
}

type A4 struct {
	Key        []byte
	Nonce      []byte
	OneTimeKey []byte
}

func getTestVectorsA4() []A4 {
	tvs := []A4{}
	// 	A.4.  Poly1305 Key Generation Using ChaCha20

	//   Test Vector #1:
	//   ==============
	tv1 := A4{}
	//   The ChaCha20 Key:
	//   000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	//   016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	tv1.Key = str2bs(
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
	)
	//   The nonce:
	//   000  00 00 00 00 00 00 00 00 00 00 00 00              ............
	tv1.Nonce = str2bs(
		"00 00 00 00 00 00 00 00 00 00 00 00",
	)
	//   Poly1305 one-time key:
	//   000  76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28  v.....=.@]j.S..(
	//   016  bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7  .........6...w..
	tv1.OneTimeKey = str2bs(
		"76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28",
		"bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7",
	)
	tvs = append(tvs, tv1)
	// Test Vector #2:
	// ==============
	tv2 := A4{}
	// The ChaCha20 Key
	// 000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	// 016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01  ................
	tv2.Key = str2bs(
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
		"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01",
	)
	// The nonce:
	// 000  00 00 00 00 00 00 00 00 00 00 00 02              ............
	tv2.Nonce = str2bs(
		"00 00 00 00 00 00 00 00 00 00 00 02",
	)
	// Poly1305 one-time key:
	// 000  ec fa 25 4f 84 5f 64 74 73 d3 cb 14 0d a9 e8 76  ..%O._dts......v
	// 016  06 cb 33 06 6c 44 7b 87 bc 26 66 dd e3 fb b7 39  ..3.lD{..&f....9
	tv2.OneTimeKey = str2bs(
		"ec fa 25 4f 84 5f 64 74 73 d3 cb 14 0d a9 e8 76",
		"06 cb 33 06 6c 44 7b 87 bc 26 66 dd e3 fb b7 39",
	)
	tvs = append(tvs, tv2)
	// Test Vector #3:
	// ==============
	tv3 := A4{}
	// The ChaCha20 Key
	// 000  1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0  ..@..U...3......
	// 016  47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0  G9..@+....\. pu.
	tv3.Key = str2bs(
		"1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0",
		"47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0",
	)
	// The nonce:
	// 000  00 00 00 00 00 00 00 00 00 00 00 02              ............
	tv3.Nonce = str2bs(
		"00 00 00 00 00 00 00 00 00 00 00 02",
	)
	// Poly1305 one-time key:
	// 000  96 5e 3b c6 f9 ec 7e d9 56 08 08 f4 d2 29 f9 4b  .^;...~.V....).K
	// 016  13 7f f2 75 ca 9b 3f cb dd 59 de aa d2 33 10 ae  ...u..?..Y...3..
	tv3.OneTimeKey = str2bs(
		"96 5e 3b c6 f9 ec 7e d9 56 08 08 f4 d2 29 f9 4b",
		"13 7f f2 75 ca 9b 3f cb dd 59 de aa d2 33 10 ae",
	)
	tvs = append(tvs, tv3)
	return tvs
}
