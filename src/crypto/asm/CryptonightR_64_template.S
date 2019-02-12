#ifdef __APPLE__
#   define ALIGN(x) .align 6
#else
#   define ALIGN(x) .align 64
#endif
.intel_syntax noprefix
#ifdef __APPLE__
#   define FN_PREFIX(fn) _ ## fn
.text
#else
#   define FN_PREFIX(fn) fn
.section .text
#endif

#define PUBLIC .global

PUBLIC FN_PREFIX(CryptonightR_64_instruction0)
PUBLIC FN_PREFIX(CryptonightR_64_instruction1)
PUBLIC FN_PREFIX(CryptonightR_64_instruction2)
PUBLIC FN_PREFIX(CryptonightR_64_instruction3)
PUBLIC FN_PREFIX(CryptonightR_64_instruction4)
PUBLIC FN_PREFIX(CryptonightR_64_instruction5)
PUBLIC FN_PREFIX(CryptonightR_64_instruction6)
PUBLIC FN_PREFIX(CryptonightR_64_instruction7)
PUBLIC FN_PREFIX(CryptonightR_64_instruction8)
PUBLIC FN_PREFIX(CryptonightR_64_instruction9)
PUBLIC FN_PREFIX(CryptonightR_64_instruction10)
PUBLIC FN_PREFIX(CryptonightR_64_instruction11)
PUBLIC FN_PREFIX(CryptonightR_64_instruction12)
PUBLIC FN_PREFIX(CryptonightR_64_instruction13)
PUBLIC FN_PREFIX(CryptonightR_64_instruction14)
PUBLIC FN_PREFIX(CryptonightR_64_instruction15)
PUBLIC FN_PREFIX(CryptonightR_64_instruction16)
PUBLIC FN_PREFIX(CryptonightR_64_instruction17)
PUBLIC FN_PREFIX(CryptonightR_64_instruction18)
PUBLIC FN_PREFIX(CryptonightR_64_instruction19)
PUBLIC FN_PREFIX(CryptonightR_64_instruction20)
PUBLIC FN_PREFIX(CryptonightR_64_instruction21)
PUBLIC FN_PREFIX(CryptonightR_64_instruction22)
PUBLIC FN_PREFIX(CryptonightR_64_instruction23)
PUBLIC FN_PREFIX(CryptonightR_64_instruction24)
PUBLIC FN_PREFIX(CryptonightR_64_instruction25)
PUBLIC FN_PREFIX(CryptonightR_64_instruction26)
PUBLIC FN_PREFIX(CryptonightR_64_instruction27)
PUBLIC FN_PREFIX(CryptonightR_64_instruction28)
PUBLIC FN_PREFIX(CryptonightR_64_instruction29)
PUBLIC FN_PREFIX(CryptonightR_64_instruction30)
PUBLIC FN_PREFIX(CryptonightR_64_instruction31)
PUBLIC FN_PREFIX(CryptonightR_64_instruction32)
PUBLIC FN_PREFIX(CryptonightR_64_instruction33)
PUBLIC FN_PREFIX(CryptonightR_64_instruction34)
PUBLIC FN_PREFIX(CryptonightR_64_instruction35)
PUBLIC FN_PREFIX(CryptonightR_64_instruction36)
PUBLIC FN_PREFIX(CryptonightR_64_instruction37)
PUBLIC FN_PREFIX(CryptonightR_64_instruction38)
PUBLIC FN_PREFIX(CryptonightR_64_instruction39)
PUBLIC FN_PREFIX(CryptonightR_64_instruction40)
PUBLIC FN_PREFIX(CryptonightR_64_instruction41)
PUBLIC FN_PREFIX(CryptonightR_64_instruction42)
PUBLIC FN_PREFIX(CryptonightR_64_instruction43)
PUBLIC FN_PREFIX(CryptonightR_64_instruction44)
PUBLIC FN_PREFIX(CryptonightR_64_instruction45)
PUBLIC FN_PREFIX(CryptonightR_64_instruction46)
PUBLIC FN_PREFIX(CryptonightR_64_instruction47)
PUBLIC FN_PREFIX(CryptonightR_64_instruction48)
PUBLIC FN_PREFIX(CryptonightR_64_instruction49)
PUBLIC FN_PREFIX(CryptonightR_64_instruction50)
PUBLIC FN_PREFIX(CryptonightR_64_instruction51)
PUBLIC FN_PREFIX(CryptonightR_64_instruction52)
PUBLIC FN_PREFIX(CryptonightR_64_instruction53)
PUBLIC FN_PREFIX(CryptonightR_64_instruction54)
PUBLIC FN_PREFIX(CryptonightR_64_instruction55)
PUBLIC FN_PREFIX(CryptonightR_64_instruction56)
PUBLIC FN_PREFIX(CryptonightR_64_instruction57)
PUBLIC FN_PREFIX(CryptonightR_64_instruction58)
PUBLIC FN_PREFIX(CryptonightR_64_instruction59)
PUBLIC FN_PREFIX(CryptonightR_64_instruction60)
PUBLIC FN_PREFIX(CryptonightR_64_instruction61)
PUBLIC FN_PREFIX(CryptonightR_64_instruction62)
PUBLIC FN_PREFIX(CryptonightR_64_instruction63)
PUBLIC FN_PREFIX(CryptonightR_64_instruction64)
PUBLIC FN_PREFIX(CryptonightR_64_instruction65)
PUBLIC FN_PREFIX(CryptonightR_64_instruction66)
PUBLIC FN_PREFIX(CryptonightR_64_instruction67)
PUBLIC FN_PREFIX(CryptonightR_64_instruction68)
PUBLIC FN_PREFIX(CryptonightR_64_instruction69)
PUBLIC FN_PREFIX(CryptonightR_64_instruction70)
PUBLIC FN_PREFIX(CryptonightR_64_instruction71)
PUBLIC FN_PREFIX(CryptonightR_64_instruction72)
PUBLIC FN_PREFIX(CryptonightR_64_instruction73)
PUBLIC FN_PREFIX(CryptonightR_64_instruction74)
PUBLIC FN_PREFIX(CryptonightR_64_instruction75)
PUBLIC FN_PREFIX(CryptonightR_64_instruction76)
PUBLIC FN_PREFIX(CryptonightR_64_instruction77)
PUBLIC FN_PREFIX(CryptonightR_64_instruction78)
PUBLIC FN_PREFIX(CryptonightR_64_instruction79)
PUBLIC FN_PREFIX(CryptonightR_64_instruction80)
PUBLIC FN_PREFIX(CryptonightR_64_instruction81)
PUBLIC FN_PREFIX(CryptonightR_64_instruction82)
PUBLIC FN_PREFIX(CryptonightR_64_instruction83)
PUBLIC FN_PREFIX(CryptonightR_64_instruction84)
PUBLIC FN_PREFIX(CryptonightR_64_instruction85)
PUBLIC FN_PREFIX(CryptonightR_64_instruction86)
PUBLIC FN_PREFIX(CryptonightR_64_instruction87)
PUBLIC FN_PREFIX(CryptonightR_64_instruction88)
PUBLIC FN_PREFIX(CryptonightR_64_instruction89)
PUBLIC FN_PREFIX(CryptonightR_64_instruction90)
PUBLIC FN_PREFIX(CryptonightR_64_instruction91)
PUBLIC FN_PREFIX(CryptonightR_64_instruction92)
PUBLIC FN_PREFIX(CryptonightR_64_instruction93)
PUBLIC FN_PREFIX(CryptonightR_64_instruction94)
PUBLIC FN_PREFIX(CryptonightR_64_instruction95)
PUBLIC FN_PREFIX(CryptonightR_64_instruction96)
PUBLIC FN_PREFIX(CryptonightR_64_instruction97)
PUBLIC FN_PREFIX(CryptonightR_64_instruction98)
PUBLIC FN_PREFIX(CryptonightR_64_instruction99)
PUBLIC FN_PREFIX(CryptonightR_64_instruction100)
PUBLIC FN_PREFIX(CryptonightR_64_instruction101)
PUBLIC FN_PREFIX(CryptonightR_64_instruction102)
PUBLIC FN_PREFIX(CryptonightR_64_instruction103)
PUBLIC FN_PREFIX(CryptonightR_64_instruction104)
PUBLIC FN_PREFIX(CryptonightR_64_instruction105)
PUBLIC FN_PREFIX(CryptonightR_64_instruction106)
PUBLIC FN_PREFIX(CryptonightR_64_instruction107)
PUBLIC FN_PREFIX(CryptonightR_64_instruction108)
PUBLIC FN_PREFIX(CryptonightR_64_instruction109)
PUBLIC FN_PREFIX(CryptonightR_64_instruction110)
PUBLIC FN_PREFIX(CryptonightR_64_instruction111)
PUBLIC FN_PREFIX(CryptonightR_64_instruction112)
PUBLIC FN_PREFIX(CryptonightR_64_instruction113)
PUBLIC FN_PREFIX(CryptonightR_64_instruction114)
PUBLIC FN_PREFIX(CryptonightR_64_instruction115)
PUBLIC FN_PREFIX(CryptonightR_64_instruction116)
PUBLIC FN_PREFIX(CryptonightR_64_instruction117)
PUBLIC FN_PREFIX(CryptonightR_64_instruction118)
PUBLIC FN_PREFIX(CryptonightR_64_instruction119)
PUBLIC FN_PREFIX(CryptonightR_64_instruction120)
PUBLIC FN_PREFIX(CryptonightR_64_instruction121)
PUBLIC FN_PREFIX(CryptonightR_64_instruction122)
PUBLIC FN_PREFIX(CryptonightR_64_instruction123)
PUBLIC FN_PREFIX(CryptonightR_64_instruction124)
PUBLIC FN_PREFIX(CryptonightR_64_instruction125)
PUBLIC FN_PREFIX(CryptonightR_64_instruction126)
PUBLIC FN_PREFIX(CryptonightR_64_instruction127)
PUBLIC FN_PREFIX(CryptonightR_64_instruction128)
PUBLIC FN_PREFIX(CryptonightR_64_instruction129)
PUBLIC FN_PREFIX(CryptonightR_64_instruction130)
PUBLIC FN_PREFIX(CryptonightR_64_instruction131)
PUBLIC FN_PREFIX(CryptonightR_64_instruction132)
PUBLIC FN_PREFIX(CryptonightR_64_instruction133)
PUBLIC FN_PREFIX(CryptonightR_64_instruction134)
PUBLIC FN_PREFIX(CryptonightR_64_instruction135)
PUBLIC FN_PREFIX(CryptonightR_64_instruction136)
PUBLIC FN_PREFIX(CryptonightR_64_instruction137)
PUBLIC FN_PREFIX(CryptonightR_64_instruction138)
PUBLIC FN_PREFIX(CryptonightR_64_instruction139)
PUBLIC FN_PREFIX(CryptonightR_64_instruction140)
PUBLIC FN_PREFIX(CryptonightR_64_instruction141)
PUBLIC FN_PREFIX(CryptonightR_64_instruction142)
PUBLIC FN_PREFIX(CryptonightR_64_instruction143)
PUBLIC FN_PREFIX(CryptonightR_64_instruction144)
PUBLIC FN_PREFIX(CryptonightR_64_instruction145)
PUBLIC FN_PREFIX(CryptonightR_64_instruction146)
PUBLIC FN_PREFIX(CryptonightR_64_instruction147)
PUBLIC FN_PREFIX(CryptonightR_64_instruction148)
PUBLIC FN_PREFIX(CryptonightR_64_instruction149)
PUBLIC FN_PREFIX(CryptonightR_64_instruction150)
PUBLIC FN_PREFIX(CryptonightR_64_instruction151)
PUBLIC FN_PREFIX(CryptonightR_64_instruction152)
PUBLIC FN_PREFIX(CryptonightR_64_instruction153)
PUBLIC FN_PREFIX(CryptonightR_64_instruction154)
PUBLIC FN_PREFIX(CryptonightR_64_instruction155)
PUBLIC FN_PREFIX(CryptonightR_64_instruction156)
PUBLIC FN_PREFIX(CryptonightR_64_instruction157)
PUBLIC FN_PREFIX(CryptonightR_64_instruction158)
PUBLIC FN_PREFIX(CryptonightR_64_instruction159)
PUBLIC FN_PREFIX(CryptonightR_64_instruction160)
PUBLIC FN_PREFIX(CryptonightR_64_instruction161)
PUBLIC FN_PREFIX(CryptonightR_64_instruction162)
PUBLIC FN_PREFIX(CryptonightR_64_instruction163)
PUBLIC FN_PREFIX(CryptonightR_64_instruction164)
PUBLIC FN_PREFIX(CryptonightR_64_instruction165)
PUBLIC FN_PREFIX(CryptonightR_64_instruction166)
PUBLIC FN_PREFIX(CryptonightR_64_instruction167)
PUBLIC FN_PREFIX(CryptonightR_64_instruction168)
PUBLIC FN_PREFIX(CryptonightR_64_instruction169)
PUBLIC FN_PREFIX(CryptonightR_64_instruction170)
PUBLIC FN_PREFIX(CryptonightR_64_instruction171)
PUBLIC FN_PREFIX(CryptonightR_64_instruction172)
PUBLIC FN_PREFIX(CryptonightR_64_instruction173)
PUBLIC FN_PREFIX(CryptonightR_64_instruction174)
PUBLIC FN_PREFIX(CryptonightR_64_instruction175)
PUBLIC FN_PREFIX(CryptonightR_64_instruction176)
PUBLIC FN_PREFIX(CryptonightR_64_instruction177)
PUBLIC FN_PREFIX(CryptonightR_64_instruction178)
PUBLIC FN_PREFIX(CryptonightR_64_instruction179)
PUBLIC FN_PREFIX(CryptonightR_64_instruction180)
PUBLIC FN_PREFIX(CryptonightR_64_instruction181)
PUBLIC FN_PREFIX(CryptonightR_64_instruction182)
PUBLIC FN_PREFIX(CryptonightR_64_instruction183)
PUBLIC FN_PREFIX(CryptonightR_64_instruction184)
PUBLIC FN_PREFIX(CryptonightR_64_instruction185)
PUBLIC FN_PREFIX(CryptonightR_64_instruction186)
PUBLIC FN_PREFIX(CryptonightR_64_instruction187)
PUBLIC FN_PREFIX(CryptonightR_64_instruction188)
PUBLIC FN_PREFIX(CryptonightR_64_instruction189)
PUBLIC FN_PREFIX(CryptonightR_64_instruction190)
PUBLIC FN_PREFIX(CryptonightR_64_instruction191)
PUBLIC FN_PREFIX(CryptonightR_64_instruction192)
PUBLIC FN_PREFIX(CryptonightR_64_instruction193)
PUBLIC FN_PREFIX(CryptonightR_64_instruction194)
PUBLIC FN_PREFIX(CryptonightR_64_instruction195)
PUBLIC FN_PREFIX(CryptonightR_64_instruction196)
PUBLIC FN_PREFIX(CryptonightR_64_instruction197)
PUBLIC FN_PREFIX(CryptonightR_64_instruction198)
PUBLIC FN_PREFIX(CryptonightR_64_instruction199)
PUBLIC FN_PREFIX(CryptonightR_64_instruction200)
PUBLIC FN_PREFIX(CryptonightR_64_instruction201)
PUBLIC FN_PREFIX(CryptonightR_64_instruction202)
PUBLIC FN_PREFIX(CryptonightR_64_instruction203)
PUBLIC FN_PREFIX(CryptonightR_64_instruction204)
PUBLIC FN_PREFIX(CryptonightR_64_instruction205)
PUBLIC FN_PREFIX(CryptonightR_64_instruction206)
PUBLIC FN_PREFIX(CryptonightR_64_instruction207)
PUBLIC FN_PREFIX(CryptonightR_64_instruction208)
PUBLIC FN_PREFIX(CryptonightR_64_instruction209)
PUBLIC FN_PREFIX(CryptonightR_64_instruction210)
PUBLIC FN_PREFIX(CryptonightR_64_instruction211)
PUBLIC FN_PREFIX(CryptonightR_64_instruction212)
PUBLIC FN_PREFIX(CryptonightR_64_instruction213)
PUBLIC FN_PREFIX(CryptonightR_64_instruction214)
PUBLIC FN_PREFIX(CryptonightR_64_instruction215)
PUBLIC FN_PREFIX(CryptonightR_64_instruction216)
PUBLIC FN_PREFIX(CryptonightR_64_instruction217)
PUBLIC FN_PREFIX(CryptonightR_64_instruction218)
PUBLIC FN_PREFIX(CryptonightR_64_instruction219)
PUBLIC FN_PREFIX(CryptonightR_64_instruction220)
PUBLIC FN_PREFIX(CryptonightR_64_instruction221)
PUBLIC FN_PREFIX(CryptonightR_64_instruction222)
PUBLIC FN_PREFIX(CryptonightR_64_instruction223)
PUBLIC FN_PREFIX(CryptonightR_64_instruction224)
PUBLIC FN_PREFIX(CryptonightR_64_instruction225)
PUBLIC FN_PREFIX(CryptonightR_64_instruction226)
PUBLIC FN_PREFIX(CryptonightR_64_instruction227)
PUBLIC FN_PREFIX(CryptonightR_64_instruction228)
PUBLIC FN_PREFIX(CryptonightR_64_instruction229)
PUBLIC FN_PREFIX(CryptonightR_64_instruction230)
PUBLIC FN_PREFIX(CryptonightR_64_instruction231)
PUBLIC FN_PREFIX(CryptonightR_64_instruction232)
PUBLIC FN_PREFIX(CryptonightR_64_instruction233)
PUBLIC FN_PREFIX(CryptonightR_64_instruction234)
PUBLIC FN_PREFIX(CryptonightR_64_instruction235)
PUBLIC FN_PREFIX(CryptonightR_64_instruction236)
PUBLIC FN_PREFIX(CryptonightR_64_instruction237)
PUBLIC FN_PREFIX(CryptonightR_64_instruction238)
PUBLIC FN_PREFIX(CryptonightR_64_instruction239)
PUBLIC FN_PREFIX(CryptonightR_64_instruction240)
PUBLIC FN_PREFIX(CryptonightR_64_instruction241)
PUBLIC FN_PREFIX(CryptonightR_64_instruction242)
PUBLIC FN_PREFIX(CryptonightR_64_instruction243)
PUBLIC FN_PREFIX(CryptonightR_64_instruction244)
PUBLIC FN_PREFIX(CryptonightR_64_instruction245)
PUBLIC FN_PREFIX(CryptonightR_64_instruction246)
PUBLIC FN_PREFIX(CryptonightR_64_instruction247)
PUBLIC FN_PREFIX(CryptonightR_64_instruction248)
PUBLIC FN_PREFIX(CryptonightR_64_instruction249)
PUBLIC FN_PREFIX(CryptonightR_64_instruction250)
PUBLIC FN_PREFIX(CryptonightR_64_instruction251)
PUBLIC FN_PREFIX(CryptonightR_64_instruction252)
PUBLIC FN_PREFIX(CryptonightR_64_instruction253)
PUBLIC FN_PREFIX(CryptonightR_64_instruction254)
PUBLIC FN_PREFIX(CryptonightR_64_instruction255)
PUBLIC FN_PREFIX(CryptonightR_64_instruction256)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov0)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov1)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov2)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov3)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov4)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov5)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov6)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov7)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov8)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov9)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov10)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov11)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov12)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov13)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov14)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov15)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov16)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov17)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov18)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov19)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov20)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov21)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov22)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov23)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov24)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov25)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov26)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov27)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov28)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov29)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov30)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov31)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov32)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov33)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov34)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov35)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov36)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov37)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov38)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov39)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov40)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov41)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov42)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov43)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov44)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov45)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov46)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov47)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov48)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov49)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov50)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov51)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov52)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov53)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov54)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov55)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov56)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov57)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov58)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov59)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov60)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov61)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov62)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov63)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov64)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov65)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov66)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov67)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov68)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov69)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov70)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov71)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov72)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov73)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov74)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov75)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov76)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov77)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov78)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov79)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov80)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov81)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov82)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov83)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov84)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov85)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov86)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov87)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov88)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov89)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov90)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov91)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov92)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov93)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov94)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov95)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov96)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov97)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov98)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov99)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov100)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov101)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov102)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov103)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov104)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov105)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov106)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov107)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov108)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov109)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov110)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov111)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov112)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov113)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov114)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov115)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov116)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov117)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov118)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov119)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov120)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov121)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov122)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov123)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov124)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov125)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov126)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov127)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov128)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov129)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov130)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov131)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov132)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov133)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov134)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov135)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov136)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov137)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov138)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov139)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov140)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov141)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov142)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov143)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov144)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov145)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov146)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov147)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov148)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov149)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov150)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov151)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov152)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov153)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov154)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov155)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov156)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov157)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov158)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov159)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov160)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov161)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov162)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov163)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov164)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov165)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov166)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov167)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov168)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov169)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov170)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov171)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov172)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov173)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov174)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov175)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov176)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov177)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov178)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov179)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov180)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov181)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov182)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov183)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov184)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov185)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov186)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov187)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov188)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov189)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov190)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov191)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov192)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov193)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov194)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov195)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov196)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov197)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov198)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov199)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov200)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov201)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov202)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov203)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov204)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov205)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov206)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov207)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov208)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov209)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov210)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov211)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov212)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov213)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov214)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov215)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov216)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov217)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov218)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov219)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov220)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov221)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov222)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov223)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov224)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov225)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov226)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov227)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov228)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov229)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov230)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov231)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov232)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov233)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov234)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov235)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov236)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov237)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov238)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov239)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov240)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov241)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov242)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov243)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov244)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov245)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov246)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov247)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov248)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov249)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov250)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov251)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov252)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov253)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov254)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov255)
PUBLIC FN_PREFIX(CryptonightR_64_instruction_mov256)

#include "CryptonightR_64_template.inc"

FN_PREFIX(CryptonightR_64_instruction0):
	imul	rbx, rbx
FN_PREFIX(CryptonightR_64_instruction1):
	imul	rbx, rbx
FN_PREFIX(CryptonightR_64_instruction2):
	imul	rbx, rbx
FN_PREFIX(CryptonightR_64_instruction3):
	add	rbx, r9
	mov ecx, 2147483647
	add	rbx, rcx
FN_PREFIX(CryptonightR_64_instruction4):
	sub	rbx, r9
FN_PREFIX(CryptonightR_64_instruction5):
	ror	rbx, cl
FN_PREFIX(CryptonightR_64_instruction6):
	rol	rbx, cl
FN_PREFIX(CryptonightR_64_instruction7):
	xor	rbx, r9
FN_PREFIX(CryptonightR_64_instruction8):
	imul	rsi, rbx
FN_PREFIX(CryptonightR_64_instruction9):
	imul	rsi, rbx
FN_PREFIX(CryptonightR_64_instruction10):
	imul	rsi, rbx
FN_PREFIX(CryptonightR_64_instruction11):
	add	rsi, rbx
	mov ecx, 2147483647
	add	rsi, rcx
FN_PREFIX(CryptonightR_64_instruction12):
	sub	rsi, rbx
FN_PREFIX(CryptonightR_64_instruction13):
	ror	rsi, cl
FN_PREFIX(CryptonightR_64_instruction14):
	rol	rsi, cl
FN_PREFIX(CryptonightR_64_instruction15):
	xor	rsi, rbx
FN_PREFIX(CryptonightR_64_instruction16):
	imul	rdi, rbx
FN_PREFIX(CryptonightR_64_instruction17):
	imul	rdi, rbx
FN_PREFIX(CryptonightR_64_instruction18):
	imul	rdi, rbx
FN_PREFIX(CryptonightR_64_instruction19):
	add	rdi, rbx
	mov ecx, 2147483647
	add	rdi, rcx
FN_PREFIX(CryptonightR_64_instruction20):
	sub	rdi, rbx
FN_PREFIX(CryptonightR_64_instruction21):
	ror	rdi, cl
FN_PREFIX(CryptonightR_64_instruction22):
	rol	rdi, cl
FN_PREFIX(CryptonightR_64_instruction23):
	xor	rdi, rbx
FN_PREFIX(CryptonightR_64_instruction24):
	imul	rbp, rbx
FN_PREFIX(CryptonightR_64_instruction25):
	imul	rbp, rbx
FN_PREFIX(CryptonightR_64_instruction26):
	imul	rbp, rbx
FN_PREFIX(CryptonightR_64_instruction27):
	add	rbp, rbx
	mov ecx, 2147483647
	add	rbp, rcx
FN_PREFIX(CryptonightR_64_instruction28):
	sub	rbp, rbx
FN_PREFIX(CryptonightR_64_instruction29):
	ror	rbp, cl
FN_PREFIX(CryptonightR_64_instruction30):
	rol	rbp, cl
FN_PREFIX(CryptonightR_64_instruction31):
	xor	rbp, rbx
FN_PREFIX(CryptonightR_64_instruction32):
	imul	rbx, rsi
FN_PREFIX(CryptonightR_64_instruction33):
	imul	rbx, rsi
FN_PREFIX(CryptonightR_64_instruction34):
	imul	rbx, rsi
FN_PREFIX(CryptonightR_64_instruction35):
	add	rbx, rsi
	mov ecx, 2147483647
	add	rbx, rcx
FN_PREFIX(CryptonightR_64_instruction36):
	sub	rbx, rsi
FN_PREFIX(CryptonightR_64_instruction37):
	ror	rbx, cl
FN_PREFIX(CryptonightR_64_instruction38):
	rol	rbx, cl
FN_PREFIX(CryptonightR_64_instruction39):
	xor	rbx, rsi
FN_PREFIX(CryptonightR_64_instruction40):
	imul	rsi, rsi
FN_PREFIX(CryptonightR_64_instruction41):
	imul	rsi, rsi
FN_PREFIX(CryptonightR_64_instruction42):
	imul	rsi, rsi
FN_PREFIX(CryptonightR_64_instruction43):
	add	rsi, r9
	mov ecx, 2147483647
	add	rsi, rcx
FN_PREFIX(CryptonightR_64_instruction44):
	sub	rsi, r9
FN_PREFIX(CryptonightR_64_instruction45):
	ror	rsi, cl
FN_PREFIX(CryptonightR_64_instruction46):
	rol	rsi, cl
FN_PREFIX(CryptonightR_64_instruction47):
	xor	rsi, r9
FN_PREFIX(CryptonightR_64_instruction48):
	imul	rdi, rsi
FN_PREFIX(CryptonightR_64_instruction49):
	imul	rdi, rsi
FN_PREFIX(CryptonightR_64_instruction50):
	imul	rdi, rsi
FN_PREFIX(CryptonightR_64_instruction51):
	add	rdi, rsi
	mov ecx, 2147483647
	add	rdi, rcx
FN_PREFIX(CryptonightR_64_instruction52):
	sub	rdi, rsi
FN_PREFIX(CryptonightR_64_instruction53):
	ror	rdi, cl
FN_PREFIX(CryptonightR_64_instruction54):
	rol	rdi, cl
FN_PREFIX(CryptonightR_64_instruction55):
	xor	rdi, rsi
FN_PREFIX(CryptonightR_64_instruction56):
	imul	rbp, rsi
FN_PREFIX(CryptonightR_64_instruction57):
	imul	rbp, rsi
FN_PREFIX(CryptonightR_64_instruction58):
	imul	rbp, rsi
FN_PREFIX(CryptonightR_64_instruction59):
	add	rbp, rsi
	mov ecx, 2147483647
	add	rbp, rcx
FN_PREFIX(CryptonightR_64_instruction60):
	sub	rbp, rsi
FN_PREFIX(CryptonightR_64_instruction61):
	ror	rbp, cl
FN_PREFIX(CryptonightR_64_instruction62):
	rol	rbp, cl
FN_PREFIX(CryptonightR_64_instruction63):
	xor	rbp, rsi
FN_PREFIX(CryptonightR_64_instruction64):
	imul	rbx, rdi
FN_PREFIX(CryptonightR_64_instruction65):
	imul	rbx, rdi
FN_PREFIX(CryptonightR_64_instruction66):
	imul	rbx, rdi
FN_PREFIX(CryptonightR_64_instruction67):
	add	rbx, rdi
	mov ecx, 2147483647
	add	rbx, rcx
FN_PREFIX(CryptonightR_64_instruction68):
	sub	rbx, rdi
FN_PREFIX(CryptonightR_64_instruction69):
	ror	rbx, cl
FN_PREFIX(CryptonightR_64_instruction70):
	rol	rbx, cl
FN_PREFIX(CryptonightR_64_instruction71):
	xor	rbx, rdi
FN_PREFIX(CryptonightR_64_instruction72):
	imul	rsi, rdi
FN_PREFIX(CryptonightR_64_instruction73):
	imul	rsi, rdi
FN_PREFIX(CryptonightR_64_instruction74):
	imul	rsi, rdi
FN_PREFIX(CryptonightR_64_instruction75):
	add	rsi, rdi
	mov ecx, 2147483647
	add	rsi, rcx
FN_PREFIX(CryptonightR_64_instruction76):
	sub	rsi, rdi
FN_PREFIX(CryptonightR_64_instruction77):
	ror	rsi, cl
FN_PREFIX(CryptonightR_64_instruction78):
	rol	rsi, cl
FN_PREFIX(CryptonightR_64_instruction79):
	xor	rsi, rdi
FN_PREFIX(CryptonightR_64_instruction80):
	imul	rdi, rdi
FN_PREFIX(CryptonightR_64_instruction81):
	imul	rdi, rdi
FN_PREFIX(CryptonightR_64_instruction82):
	imul	rdi, rdi
FN_PREFIX(CryptonightR_64_instruction83):
	add	rdi, r9
	mov ecx, 2147483647
	add	rdi, rcx
FN_PREFIX(CryptonightR_64_instruction84):
	sub	rdi, r9
FN_PREFIX(CryptonightR_64_instruction85):
	ror	rdi, cl
FN_PREFIX(CryptonightR_64_instruction86):
	rol	rdi, cl
FN_PREFIX(CryptonightR_64_instruction87):
	xor	rdi, r9
FN_PREFIX(CryptonightR_64_instruction88):
	imul	rbp, rdi
FN_PREFIX(CryptonightR_64_instruction89):
	imul	rbp, rdi
FN_PREFIX(CryptonightR_64_instruction90):
	imul	rbp, rdi
FN_PREFIX(CryptonightR_64_instruction91):
	add	rbp, rdi
	mov ecx, 2147483647
	add	rbp, rcx
FN_PREFIX(CryptonightR_64_instruction92):
	sub	rbp, rdi
FN_PREFIX(CryptonightR_64_instruction93):
	ror	rbp, cl
FN_PREFIX(CryptonightR_64_instruction94):
	rol	rbp, cl
FN_PREFIX(CryptonightR_64_instruction95):
	xor	rbp, rdi
FN_PREFIX(CryptonightR_64_instruction96):
	imul	rbx, rbp
FN_PREFIX(CryptonightR_64_instruction97):
	imul	rbx, rbp
FN_PREFIX(CryptonightR_64_instruction98):
	imul	rbx, rbp
FN_PREFIX(CryptonightR_64_instruction99):
	add	rbx, rbp
	mov ecx, 2147483647
	add	rbx, rcx
FN_PREFIX(CryptonightR_64_instruction100):
	sub	rbx, rbp
FN_PREFIX(CryptonightR_64_instruction101):
	ror	rbx, cl
FN_PREFIX(CryptonightR_64_instruction102):
	rol	rbx, cl
FN_PREFIX(CryptonightR_64_instruction103):
	xor	rbx, rbp
FN_PREFIX(CryptonightR_64_instruction104):
	imul	rsi, rbp
FN_PREFIX(CryptonightR_64_instruction105):
	imul	rsi, rbp
FN_PREFIX(CryptonightR_64_instruction106):
	imul	rsi, rbp
FN_PREFIX(CryptonightR_64_instruction107):
	add	rsi, rbp
	mov ecx, 2147483647
	add	rsi, rcx
FN_PREFIX(CryptonightR_64_instruction108):
	sub	rsi, rbp
FN_PREFIX(CryptonightR_64_instruction109):
	ror	rsi, cl
FN_PREFIX(CryptonightR_64_instruction110):
	rol	rsi, cl
FN_PREFIX(CryptonightR_64_instruction111):
	xor	rsi, rbp
FN_PREFIX(CryptonightR_64_instruction112):
	imul	rdi, rbp
FN_PREFIX(CryptonightR_64_instruction113):
	imul	rdi, rbp
FN_PREFIX(CryptonightR_64_instruction114):
	imul	rdi, rbp
FN_PREFIX(CryptonightR_64_instruction115):
	add	rdi, rbp
	mov ecx, 2147483647
	add	rdi, rcx
FN_PREFIX(CryptonightR_64_instruction116):
	sub	rdi, rbp
FN_PREFIX(CryptonightR_64_instruction117):
	ror	rdi, cl
FN_PREFIX(CryptonightR_64_instruction118):
	rol	rdi, cl
FN_PREFIX(CryptonightR_64_instruction119):
	xor	rdi, rbp
FN_PREFIX(CryptonightR_64_instruction120):
	imul	rbp, rbp
FN_PREFIX(CryptonightR_64_instruction121):
	imul	rbp, rbp
FN_PREFIX(CryptonightR_64_instruction122):
	imul	rbp, rbp
FN_PREFIX(CryptonightR_64_instruction123):
	add	rbp, r9
	mov ecx, 2147483647
	add	rbp, rcx
FN_PREFIX(CryptonightR_64_instruction124):
	sub	rbp, r9
FN_PREFIX(CryptonightR_64_instruction125):
	ror	rbp, cl
FN_PREFIX(CryptonightR_64_instruction126):
	rol	rbp, cl
FN_PREFIX(CryptonightR_64_instruction127):
	xor	rbp, r9
FN_PREFIX(CryptonightR_64_instruction128):
	imul	rbx, rsp
FN_PREFIX(CryptonightR_64_instruction129):
	imul	rbx, rsp
FN_PREFIX(CryptonightR_64_instruction130):
	imul	rbx, rsp
FN_PREFIX(CryptonightR_64_instruction131):
	add	rbx, rsp
	mov ecx, 2147483647
	add	rbx, rcx
FN_PREFIX(CryptonightR_64_instruction132):
	sub	rbx, rsp
FN_PREFIX(CryptonightR_64_instruction133):
	ror	rbx, cl
FN_PREFIX(CryptonightR_64_instruction134):
	rol	rbx, cl
FN_PREFIX(CryptonightR_64_instruction135):
	xor	rbx, rsp
FN_PREFIX(CryptonightR_64_instruction136):
	imul	rsi, rsp
FN_PREFIX(CryptonightR_64_instruction137):
	imul	rsi, rsp
FN_PREFIX(CryptonightR_64_instruction138):
	imul	rsi, rsp
FN_PREFIX(CryptonightR_64_instruction139):
	add	rsi, rsp
	mov ecx, 2147483647
	add	rsi, rcx
FN_PREFIX(CryptonightR_64_instruction140):
	sub	rsi, rsp
FN_PREFIX(CryptonightR_64_instruction141):
	ror	rsi, cl
FN_PREFIX(CryptonightR_64_instruction142):
	rol	rsi, cl
FN_PREFIX(CryptonightR_64_instruction143):
	xor	rsi, rsp
FN_PREFIX(CryptonightR_64_instruction144):
	imul	rdi, rsp
FN_PREFIX(CryptonightR_64_instruction145):
	imul	rdi, rsp
FN_PREFIX(CryptonightR_64_instruction146):
	imul	rdi, rsp
FN_PREFIX(CryptonightR_64_instruction147):
	add	rdi, rsp
	mov ecx, 2147483647
	add	rdi, rcx
FN_PREFIX(CryptonightR_64_instruction148):
	sub	rdi, rsp
FN_PREFIX(CryptonightR_64_instruction149):
	ror	rdi, cl
FN_PREFIX(CryptonightR_64_instruction150):
	rol	rdi, cl
FN_PREFIX(CryptonightR_64_instruction151):
	xor	rdi, rsp
FN_PREFIX(CryptonightR_64_instruction152):
	imul	rbp, rsp
FN_PREFIX(CryptonightR_64_instruction153):
	imul	rbp, rsp
FN_PREFIX(CryptonightR_64_instruction154):
	imul	rbp, rsp
FN_PREFIX(CryptonightR_64_instruction155):
	add	rbp, rsp
	mov ecx, 2147483647
	add	rbp, rcx
FN_PREFIX(CryptonightR_64_instruction156):
	sub	rbp, rsp
FN_PREFIX(CryptonightR_64_instruction157):
	ror	rbp, cl
FN_PREFIX(CryptonightR_64_instruction158):
	rol	rbp, cl
FN_PREFIX(CryptonightR_64_instruction159):
	xor	rbp, rsp
FN_PREFIX(CryptonightR_64_instruction160):
	imul	rbx, r15
FN_PREFIX(CryptonightR_64_instruction161):
	imul	rbx, r15
FN_PREFIX(CryptonightR_64_instruction162):
	imul	rbx, r15
FN_PREFIX(CryptonightR_64_instruction163):
	add	rbx, r15
	mov ecx, 2147483647
	add	rbx, rcx
FN_PREFIX(CryptonightR_64_instruction164):
	sub	rbx, r15
FN_PREFIX(CryptonightR_64_instruction165):
	ror	rbx, cl
FN_PREFIX(CryptonightR_64_instruction166):
	rol	rbx, cl
FN_PREFIX(CryptonightR_64_instruction167):
	xor	rbx, r15
FN_PREFIX(CryptonightR_64_instruction168):
	imul	rsi, r15
FN_PREFIX(CryptonightR_64_instruction169):
	imul	rsi, r15
FN_PREFIX(CryptonightR_64_instruction170):
	imul	rsi, r15
FN_PREFIX(CryptonightR_64_instruction171):
	add	rsi, r15
	mov ecx, 2147483647
	add	rsi, rcx
FN_PREFIX(CryptonightR_64_instruction172):
	sub	rsi, r15
FN_PREFIX(CryptonightR_64_instruction173):
	ror	rsi, cl
FN_PREFIX(CryptonightR_64_instruction174):
	rol	rsi, cl
FN_PREFIX(CryptonightR_64_instruction175):
	xor	rsi, r15
FN_PREFIX(CryptonightR_64_instruction176):
	imul	rdi, r15
FN_PREFIX(CryptonightR_64_instruction177):
	imul	rdi, r15
FN_PREFIX(CryptonightR_64_instruction178):
	imul	rdi, r15
FN_PREFIX(CryptonightR_64_instruction179):
	add	rdi, r15
	mov ecx, 2147483647
	add	rdi, rcx
FN_PREFIX(CryptonightR_64_instruction180):
	sub	rdi, r15
FN_PREFIX(CryptonightR_64_instruction181):
	ror	rdi, cl
FN_PREFIX(CryptonightR_64_instruction182):
	rol	rdi, cl
FN_PREFIX(CryptonightR_64_instruction183):
	xor	rdi, r15
FN_PREFIX(CryptonightR_64_instruction184):
	imul	rbp, r15
FN_PREFIX(CryptonightR_64_instruction185):
	imul	rbp, r15
FN_PREFIX(CryptonightR_64_instruction186):
	imul	rbp, r15
FN_PREFIX(CryptonightR_64_instruction187):
	add	rbp, r15
	mov ecx, 2147483647
	add	rbp, rcx
FN_PREFIX(CryptonightR_64_instruction188):
	sub	rbp, r15
FN_PREFIX(CryptonightR_64_instruction189):
	ror	rbp, cl
FN_PREFIX(CryptonightR_64_instruction190):
	rol	rbp, cl
FN_PREFIX(CryptonightR_64_instruction191):
	xor	rbp, r15
FN_PREFIX(CryptonightR_64_instruction192):
	imul	rbx, rax
FN_PREFIX(CryptonightR_64_instruction193):
	imul	rbx, rax
FN_PREFIX(CryptonightR_64_instruction194):
	imul	rbx, rax
FN_PREFIX(CryptonightR_64_instruction195):
	add	rbx, rax
	mov ecx, 2147483647
	add	rbx, rcx
FN_PREFIX(CryptonightR_64_instruction196):
	sub	rbx, rax
FN_PREFIX(CryptonightR_64_instruction197):
	ror	rbx, cl
FN_PREFIX(CryptonightR_64_instruction198):
	rol	rbx, cl
FN_PREFIX(CryptonightR_64_instruction199):
	xor	rbx, rax
FN_PREFIX(CryptonightR_64_instruction200):
	imul	rsi, rax
FN_PREFIX(CryptonightR_64_instruction201):
	imul	rsi, rax
FN_PREFIX(CryptonightR_64_instruction202):
	imul	rsi, rax
FN_PREFIX(CryptonightR_64_instruction203):
	add	rsi, rax
	mov ecx, 2147483647
	add	rsi, rcx
FN_PREFIX(CryptonightR_64_instruction204):
	sub	rsi, rax
FN_PREFIX(CryptonightR_64_instruction205):
	ror	rsi, cl
FN_PREFIX(CryptonightR_64_instruction206):
	rol	rsi, cl
FN_PREFIX(CryptonightR_64_instruction207):
	xor	rsi, rax
FN_PREFIX(CryptonightR_64_instruction208):
	imul	rdi, rax
FN_PREFIX(CryptonightR_64_instruction209):
	imul	rdi, rax
FN_PREFIX(CryptonightR_64_instruction210):
	imul	rdi, rax
FN_PREFIX(CryptonightR_64_instruction211):
	add	rdi, rax
	mov ecx, 2147483647
	add	rdi, rcx
FN_PREFIX(CryptonightR_64_instruction212):
	sub	rdi, rax
FN_PREFIX(CryptonightR_64_instruction213):
	ror	rdi, cl
FN_PREFIX(CryptonightR_64_instruction214):
	rol	rdi, cl
FN_PREFIX(CryptonightR_64_instruction215):
	xor	rdi, rax
FN_PREFIX(CryptonightR_64_instruction216):
	imul	rbp, rax
FN_PREFIX(CryptonightR_64_instruction217):
	imul	rbp, rax
FN_PREFIX(CryptonightR_64_instruction218):
	imul	rbp, rax
FN_PREFIX(CryptonightR_64_instruction219):
	add	rbp, rax
	mov ecx, 2147483647
	add	rbp, rcx
FN_PREFIX(CryptonightR_64_instruction220):
	sub	rbp, rax
FN_PREFIX(CryptonightR_64_instruction221):
	ror	rbp, cl
FN_PREFIX(CryptonightR_64_instruction222):
	rol	rbp, cl
FN_PREFIX(CryptonightR_64_instruction223):
	xor	rbp, rax
FN_PREFIX(CryptonightR_64_instruction224):
	imul	rbx, rdx
FN_PREFIX(CryptonightR_64_instruction225):
	imul	rbx, rdx
FN_PREFIX(CryptonightR_64_instruction226):
	imul	rbx, rdx
FN_PREFIX(CryptonightR_64_instruction227):
	add	rbx, rdx
	mov ecx, 2147483647
	add	rbx, rcx
FN_PREFIX(CryptonightR_64_instruction228):
	sub	rbx, rdx
FN_PREFIX(CryptonightR_64_instruction229):
	ror	rbx, cl
FN_PREFIX(CryptonightR_64_instruction230):
	rol	rbx, cl
FN_PREFIX(CryptonightR_64_instruction231):
	xor	rbx, rdx
FN_PREFIX(CryptonightR_64_instruction232):
	imul	rsi, rdx
FN_PREFIX(CryptonightR_64_instruction233):
	imul	rsi, rdx
FN_PREFIX(CryptonightR_64_instruction234):
	imul	rsi, rdx
FN_PREFIX(CryptonightR_64_instruction235):
	add	rsi, rdx
	mov ecx, 2147483647
	add	rsi, rcx
FN_PREFIX(CryptonightR_64_instruction236):
	sub	rsi, rdx
FN_PREFIX(CryptonightR_64_instruction237):
	ror	rsi, cl
FN_PREFIX(CryptonightR_64_instruction238):
	rol	rsi, cl
FN_PREFIX(CryptonightR_64_instruction239):
	xor	rsi, rdx
FN_PREFIX(CryptonightR_64_instruction240):
	imul	rdi, rdx
FN_PREFIX(CryptonightR_64_instruction241):
	imul	rdi, rdx
FN_PREFIX(CryptonightR_64_instruction242):
	imul	rdi, rdx
FN_PREFIX(CryptonightR_64_instruction243):
	add	rdi, rdx
	mov ecx, 2147483647
	add	rdi, rcx
FN_PREFIX(CryptonightR_64_instruction244):
	sub	rdi, rdx
FN_PREFIX(CryptonightR_64_instruction245):
	ror	rdi, cl
FN_PREFIX(CryptonightR_64_instruction246):
	rol	rdi, cl
FN_PREFIX(CryptonightR_64_instruction247):
	xor	rdi, rdx
FN_PREFIX(CryptonightR_64_instruction248):
	imul	rbp, rdx
FN_PREFIX(CryptonightR_64_instruction249):
	imul	rbp, rdx
FN_PREFIX(CryptonightR_64_instruction250):
	imul	rbp, rdx
FN_PREFIX(CryptonightR_64_instruction251):
	add	rbp, rdx
	mov ecx, 2147483647
	add	rbp, rcx
FN_PREFIX(CryptonightR_64_instruction252):
	sub	rbp, rdx
FN_PREFIX(CryptonightR_64_instruction253):
	ror	rbp, cl
FN_PREFIX(CryptonightR_64_instruction254):
	rol	rbp, cl
FN_PREFIX(CryptonightR_64_instruction255):
	xor	rbp, rdx
FN_PREFIX(CryptonightR_64_instruction256):
	imul	rbx, rbx
FN_PREFIX(CryptonightR_64_instruction_mov0):

FN_PREFIX(CryptonightR_64_instruction_mov1):

FN_PREFIX(CryptonightR_64_instruction_mov2):

FN_PREFIX(CryptonightR_64_instruction_mov3):

FN_PREFIX(CryptonightR_64_instruction_mov4):

FN_PREFIX(CryptonightR_64_instruction_mov5):
	mov	rcx, rbx
FN_PREFIX(CryptonightR_64_instruction_mov6):
	mov	rcx, rbx
FN_PREFIX(CryptonightR_64_instruction_mov7):

FN_PREFIX(CryptonightR_64_instruction_mov8):

FN_PREFIX(CryptonightR_64_instruction_mov9):

FN_PREFIX(CryptonightR_64_instruction_mov10):

FN_PREFIX(CryptonightR_64_instruction_mov11):

FN_PREFIX(CryptonightR_64_instruction_mov12):

FN_PREFIX(CryptonightR_64_instruction_mov13):
	mov	rcx, rbx
FN_PREFIX(CryptonightR_64_instruction_mov14):
	mov	rcx, rbx
FN_PREFIX(CryptonightR_64_instruction_mov15):

FN_PREFIX(CryptonightR_64_instruction_mov16):

FN_PREFIX(CryptonightR_64_instruction_mov17):

FN_PREFIX(CryptonightR_64_instruction_mov18):

FN_PREFIX(CryptonightR_64_instruction_mov19):

FN_PREFIX(CryptonightR_64_instruction_mov20):

FN_PREFIX(CryptonightR_64_instruction_mov21):
	mov	rcx, rbx
FN_PREFIX(CryptonightR_64_instruction_mov22):
	mov	rcx, rbx
FN_PREFIX(CryptonightR_64_instruction_mov23):

FN_PREFIX(CryptonightR_64_instruction_mov24):

FN_PREFIX(CryptonightR_64_instruction_mov25):

FN_PREFIX(CryptonightR_64_instruction_mov26):

FN_PREFIX(CryptonightR_64_instruction_mov27):

FN_PREFIX(CryptonightR_64_instruction_mov28):

FN_PREFIX(CryptonightR_64_instruction_mov29):
	mov	rcx, rbx
FN_PREFIX(CryptonightR_64_instruction_mov30):
	mov	rcx, rbx
FN_PREFIX(CryptonightR_64_instruction_mov31):

FN_PREFIX(CryptonightR_64_instruction_mov32):

FN_PREFIX(CryptonightR_64_instruction_mov33):

FN_PREFIX(CryptonightR_64_instruction_mov34):

FN_PREFIX(CryptonightR_64_instruction_mov35):

FN_PREFIX(CryptonightR_64_instruction_mov36):

FN_PREFIX(CryptonightR_64_instruction_mov37):
	mov	rcx, rsi
FN_PREFIX(CryptonightR_64_instruction_mov38):
	mov	rcx, rsi
FN_PREFIX(CryptonightR_64_instruction_mov39):

FN_PREFIX(CryptonightR_64_instruction_mov40):

FN_PREFIX(CryptonightR_64_instruction_mov41):

FN_PREFIX(CryptonightR_64_instruction_mov42):

FN_PREFIX(CryptonightR_64_instruction_mov43):

FN_PREFIX(CryptonightR_64_instruction_mov44):

FN_PREFIX(CryptonightR_64_instruction_mov45):
	mov	rcx, rsi
FN_PREFIX(CryptonightR_64_instruction_mov46):
	mov	rcx, rsi
FN_PREFIX(CryptonightR_64_instruction_mov47):

FN_PREFIX(CryptonightR_64_instruction_mov48):

FN_PREFIX(CryptonightR_64_instruction_mov49):

FN_PREFIX(CryptonightR_64_instruction_mov50):

FN_PREFIX(CryptonightR_64_instruction_mov51):

FN_PREFIX(CryptonightR_64_instruction_mov52):

FN_PREFIX(CryptonightR_64_instruction_mov53):
	mov	rcx, rsi
FN_PREFIX(CryptonightR_64_instruction_mov54):
	mov	rcx, rsi
FN_PREFIX(CryptonightR_64_instruction_mov55):

FN_PREFIX(CryptonightR_64_instruction_mov56):

FN_PREFIX(CryptonightR_64_instruction_mov57):

FN_PREFIX(CryptonightR_64_instruction_mov58):

FN_PREFIX(CryptonightR_64_instruction_mov59):

FN_PREFIX(CryptonightR_64_instruction_mov60):

FN_PREFIX(CryptonightR_64_instruction_mov61):
	mov	rcx, rsi
FN_PREFIX(CryptonightR_64_instruction_mov62):
	mov	rcx, rsi
FN_PREFIX(CryptonightR_64_instruction_mov63):

FN_PREFIX(CryptonightR_64_instruction_mov64):

FN_PREFIX(CryptonightR_64_instruction_mov65):

FN_PREFIX(CryptonightR_64_instruction_mov66):

FN_PREFIX(CryptonightR_64_instruction_mov67):

FN_PREFIX(CryptonightR_64_instruction_mov68):

FN_PREFIX(CryptonightR_64_instruction_mov69):
	mov	rcx, rdi
FN_PREFIX(CryptonightR_64_instruction_mov70):
	mov	rcx, rdi
FN_PREFIX(CryptonightR_64_instruction_mov71):

FN_PREFIX(CryptonightR_64_instruction_mov72):

FN_PREFIX(CryptonightR_64_instruction_mov73):

FN_PREFIX(CryptonightR_64_instruction_mov74):

FN_PREFIX(CryptonightR_64_instruction_mov75):

FN_PREFIX(CryptonightR_64_instruction_mov76):

FN_PREFIX(CryptonightR_64_instruction_mov77):
	mov	rcx, rdi
FN_PREFIX(CryptonightR_64_instruction_mov78):
	mov	rcx, rdi
FN_PREFIX(CryptonightR_64_instruction_mov79):

FN_PREFIX(CryptonightR_64_instruction_mov80):

FN_PREFIX(CryptonightR_64_instruction_mov81):

FN_PREFIX(CryptonightR_64_instruction_mov82):

FN_PREFIX(CryptonightR_64_instruction_mov83):

FN_PREFIX(CryptonightR_64_instruction_mov84):

FN_PREFIX(CryptonightR_64_instruction_mov85):
	mov	rcx, rdi
FN_PREFIX(CryptonightR_64_instruction_mov86):
	mov	rcx, rdi
FN_PREFIX(CryptonightR_64_instruction_mov87):

FN_PREFIX(CryptonightR_64_instruction_mov88):

FN_PREFIX(CryptonightR_64_instruction_mov89):

FN_PREFIX(CryptonightR_64_instruction_mov90):

FN_PREFIX(CryptonightR_64_instruction_mov91):

FN_PREFIX(CryptonightR_64_instruction_mov92):

FN_PREFIX(CryptonightR_64_instruction_mov93):
	mov	rcx, rdi
FN_PREFIX(CryptonightR_64_instruction_mov94):
	mov	rcx, rdi
FN_PREFIX(CryptonightR_64_instruction_mov95):

FN_PREFIX(CryptonightR_64_instruction_mov96):

FN_PREFIX(CryptonightR_64_instruction_mov97):

FN_PREFIX(CryptonightR_64_instruction_mov98):

FN_PREFIX(CryptonightR_64_instruction_mov99):

FN_PREFIX(CryptonightR_64_instruction_mov100):

FN_PREFIX(CryptonightR_64_instruction_mov101):
	mov	rcx, rbp
FN_PREFIX(CryptonightR_64_instruction_mov102):
	mov	rcx, rbp
FN_PREFIX(CryptonightR_64_instruction_mov103):

FN_PREFIX(CryptonightR_64_instruction_mov104):

FN_PREFIX(CryptonightR_64_instruction_mov105):

FN_PREFIX(CryptonightR_64_instruction_mov106):

FN_PREFIX(CryptonightR_64_instruction_mov107):

FN_PREFIX(CryptonightR_64_instruction_mov108):

FN_PREFIX(CryptonightR_64_instruction_mov109):
	mov	rcx, rbp
FN_PREFIX(CryptonightR_64_instruction_mov110):
	mov	rcx, rbp
FN_PREFIX(CryptonightR_64_instruction_mov111):

FN_PREFIX(CryptonightR_64_instruction_mov112):

FN_PREFIX(CryptonightR_64_instruction_mov113):

FN_PREFIX(CryptonightR_64_instruction_mov114):

FN_PREFIX(CryptonightR_64_instruction_mov115):

FN_PREFIX(CryptonightR_64_instruction_mov116):

FN_PREFIX(CryptonightR_64_instruction_mov117):
	mov	rcx, rbp
FN_PREFIX(CryptonightR_64_instruction_mov118):
	mov	rcx, rbp
FN_PREFIX(CryptonightR_64_instruction_mov119):

FN_PREFIX(CryptonightR_64_instruction_mov120):

FN_PREFIX(CryptonightR_64_instruction_mov121):

FN_PREFIX(CryptonightR_64_instruction_mov122):

FN_PREFIX(CryptonightR_64_instruction_mov123):

FN_PREFIX(CryptonightR_64_instruction_mov124):

FN_PREFIX(CryptonightR_64_instruction_mov125):
	mov	rcx, rbp
FN_PREFIX(CryptonightR_64_instruction_mov126):
	mov	rcx, rbp
FN_PREFIX(CryptonightR_64_instruction_mov127):

FN_PREFIX(CryptonightR_64_instruction_mov128):

FN_PREFIX(CryptonightR_64_instruction_mov129):

FN_PREFIX(CryptonightR_64_instruction_mov130):

FN_PREFIX(CryptonightR_64_instruction_mov131):

FN_PREFIX(CryptonightR_64_instruction_mov132):

FN_PREFIX(CryptonightR_64_instruction_mov133):
	mov	rcx, rsp
FN_PREFIX(CryptonightR_64_instruction_mov134):
	mov	rcx, rsp
FN_PREFIX(CryptonightR_64_instruction_mov135):

FN_PREFIX(CryptonightR_64_instruction_mov136):

FN_PREFIX(CryptonightR_64_instruction_mov137):

FN_PREFIX(CryptonightR_64_instruction_mov138):

FN_PREFIX(CryptonightR_64_instruction_mov139):

FN_PREFIX(CryptonightR_64_instruction_mov140):

FN_PREFIX(CryptonightR_64_instruction_mov141):
	mov	rcx, rsp
FN_PREFIX(CryptonightR_64_instruction_mov142):
	mov	rcx, rsp
FN_PREFIX(CryptonightR_64_instruction_mov143):

FN_PREFIX(CryptonightR_64_instruction_mov144):

FN_PREFIX(CryptonightR_64_instruction_mov145):

FN_PREFIX(CryptonightR_64_instruction_mov146):

FN_PREFIX(CryptonightR_64_instruction_mov147):

FN_PREFIX(CryptonightR_64_instruction_mov148):

FN_PREFIX(CryptonightR_64_instruction_mov149):
	mov	rcx, rsp
FN_PREFIX(CryptonightR_64_instruction_mov150):
	mov	rcx, rsp
FN_PREFIX(CryptonightR_64_instruction_mov151):

FN_PREFIX(CryptonightR_64_instruction_mov152):

FN_PREFIX(CryptonightR_64_instruction_mov153):

FN_PREFIX(CryptonightR_64_instruction_mov154):

FN_PREFIX(CryptonightR_64_instruction_mov155):

FN_PREFIX(CryptonightR_64_instruction_mov156):

FN_PREFIX(CryptonightR_64_instruction_mov157):
	mov	rcx, rsp
FN_PREFIX(CryptonightR_64_instruction_mov158):
	mov	rcx, rsp
FN_PREFIX(CryptonightR_64_instruction_mov159):

FN_PREFIX(CryptonightR_64_instruction_mov160):

FN_PREFIX(CryptonightR_64_instruction_mov161):

FN_PREFIX(CryptonightR_64_instruction_mov162):

FN_PREFIX(CryptonightR_64_instruction_mov163):

FN_PREFIX(CryptonightR_64_instruction_mov164):

FN_PREFIX(CryptonightR_64_instruction_mov165):
	mov	rcx, r15
FN_PREFIX(CryptonightR_64_instruction_mov166):
	mov	rcx, r15
FN_PREFIX(CryptonightR_64_instruction_mov167):

FN_PREFIX(CryptonightR_64_instruction_mov168):

FN_PREFIX(CryptonightR_64_instruction_mov169):

FN_PREFIX(CryptonightR_64_instruction_mov170):

FN_PREFIX(CryptonightR_64_instruction_mov171):

FN_PREFIX(CryptonightR_64_instruction_mov172):

FN_PREFIX(CryptonightR_64_instruction_mov173):
	mov	rcx, r15
FN_PREFIX(CryptonightR_64_instruction_mov174):
	mov	rcx, r15
FN_PREFIX(CryptonightR_64_instruction_mov175):

FN_PREFIX(CryptonightR_64_instruction_mov176):

FN_PREFIX(CryptonightR_64_instruction_mov177):

FN_PREFIX(CryptonightR_64_instruction_mov178):

FN_PREFIX(CryptonightR_64_instruction_mov179):

FN_PREFIX(CryptonightR_64_instruction_mov180):

FN_PREFIX(CryptonightR_64_instruction_mov181):
	mov	rcx, r15
FN_PREFIX(CryptonightR_64_instruction_mov182):
	mov	rcx, r15
FN_PREFIX(CryptonightR_64_instruction_mov183):

FN_PREFIX(CryptonightR_64_instruction_mov184):

FN_PREFIX(CryptonightR_64_instruction_mov185):

FN_PREFIX(CryptonightR_64_instruction_mov186):

FN_PREFIX(CryptonightR_64_instruction_mov187):

FN_PREFIX(CryptonightR_64_instruction_mov188):

FN_PREFIX(CryptonightR_64_instruction_mov189):
	mov	rcx, r15
FN_PREFIX(CryptonightR_64_instruction_mov190):
	mov	rcx, r15
FN_PREFIX(CryptonightR_64_instruction_mov191):

FN_PREFIX(CryptonightR_64_instruction_mov192):

FN_PREFIX(CryptonightR_64_instruction_mov193):

FN_PREFIX(CryptonightR_64_instruction_mov194):

FN_PREFIX(CryptonightR_64_instruction_mov195):

FN_PREFIX(CryptonightR_64_instruction_mov196):

FN_PREFIX(CryptonightR_64_instruction_mov197):
	mov	rcx, rax
FN_PREFIX(CryptonightR_64_instruction_mov198):
	mov	rcx, rax
FN_PREFIX(CryptonightR_64_instruction_mov199):

FN_PREFIX(CryptonightR_64_instruction_mov200):

FN_PREFIX(CryptonightR_64_instruction_mov201):

FN_PREFIX(CryptonightR_64_instruction_mov202):

FN_PREFIX(CryptonightR_64_instruction_mov203):

FN_PREFIX(CryptonightR_64_instruction_mov204):

FN_PREFIX(CryptonightR_64_instruction_mov205):
	mov	rcx, rax
FN_PREFIX(CryptonightR_64_instruction_mov206):
	mov	rcx, rax
FN_PREFIX(CryptonightR_64_instruction_mov207):

FN_PREFIX(CryptonightR_64_instruction_mov208):

FN_PREFIX(CryptonightR_64_instruction_mov209):

FN_PREFIX(CryptonightR_64_instruction_mov210):

FN_PREFIX(CryptonightR_64_instruction_mov211):

FN_PREFIX(CryptonightR_64_instruction_mov212):

FN_PREFIX(CryptonightR_64_instruction_mov213):
	mov	rcx, rax
FN_PREFIX(CryptonightR_64_instruction_mov214):
	mov	rcx, rax
FN_PREFIX(CryptonightR_64_instruction_mov215):

FN_PREFIX(CryptonightR_64_instruction_mov216):

FN_PREFIX(CryptonightR_64_instruction_mov217):

FN_PREFIX(CryptonightR_64_instruction_mov218):

FN_PREFIX(CryptonightR_64_instruction_mov219):

FN_PREFIX(CryptonightR_64_instruction_mov220):

FN_PREFIX(CryptonightR_64_instruction_mov221):
	mov	rcx, rax
FN_PREFIX(CryptonightR_64_instruction_mov222):
	mov	rcx, rax
FN_PREFIX(CryptonightR_64_instruction_mov223):

FN_PREFIX(CryptonightR_64_instruction_mov224):

FN_PREFIX(CryptonightR_64_instruction_mov225):

FN_PREFIX(CryptonightR_64_instruction_mov226):

FN_PREFIX(CryptonightR_64_instruction_mov227):

FN_PREFIX(CryptonightR_64_instruction_mov228):

FN_PREFIX(CryptonightR_64_instruction_mov229):
	mov	rcx, rdx
FN_PREFIX(CryptonightR_64_instruction_mov230):
	mov	rcx, rdx
FN_PREFIX(CryptonightR_64_instruction_mov231):

FN_PREFIX(CryptonightR_64_instruction_mov232):

FN_PREFIX(CryptonightR_64_instruction_mov233):

FN_PREFIX(CryptonightR_64_instruction_mov234):

FN_PREFIX(CryptonightR_64_instruction_mov235):

FN_PREFIX(CryptonightR_64_instruction_mov236):

FN_PREFIX(CryptonightR_64_instruction_mov237):
	mov	rcx, rdx
FN_PREFIX(CryptonightR_64_instruction_mov238):
	mov	rcx, rdx
FN_PREFIX(CryptonightR_64_instruction_mov239):

FN_PREFIX(CryptonightR_64_instruction_mov240):

FN_PREFIX(CryptonightR_64_instruction_mov241):

FN_PREFIX(CryptonightR_64_instruction_mov242):

FN_PREFIX(CryptonightR_64_instruction_mov243):

FN_PREFIX(CryptonightR_64_instruction_mov244):

FN_PREFIX(CryptonightR_64_instruction_mov245):
	mov	rcx, rdx
FN_PREFIX(CryptonightR_64_instruction_mov246):
	mov	rcx, rdx
FN_PREFIX(CryptonightR_64_instruction_mov247):

FN_PREFIX(CryptonightR_64_instruction_mov248):

FN_PREFIX(CryptonightR_64_instruction_mov249):

FN_PREFIX(CryptonightR_64_instruction_mov250):

FN_PREFIX(CryptonightR_64_instruction_mov251):

FN_PREFIX(CryptonightR_64_instruction_mov252):

FN_PREFIX(CryptonightR_64_instruction_mov253):
	mov	rcx, rdx
FN_PREFIX(CryptonightR_64_instruction_mov254):
	mov	rcx, rdx
FN_PREFIX(CryptonightR_64_instruction_mov255):

FN_PREFIX(CryptonightR_64_instruction_mov256):
