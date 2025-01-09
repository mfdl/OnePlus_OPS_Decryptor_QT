#ifndef OPSDECRYPT_H
#define OPSDECRYPT_H

#include <QObject>
#include "QtCore"
#include <QDebug>
#include <QDomDocument>
#include <QDesktopServices>

#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <windows.h>
#include <io.h>

#ifdef __cplusplus
extern "C" {
#endif

#define qnull_hnd ((HANDLE) (LONG_PTR)-1)
#ifdef __cplusplus
}
#endif

#define qMinLen(X, Y) \
    __extension__ ({ __typeof__(X) _X = (X); __typeof__(Y) _Y = (Y); _X < _Y ? _X : _Y; })

#define QCOMPARE Qt::CaseSensitive

#define QNATIVE_PATH qdir::toNativeSeparators

using namespace std;

#define qnull nullptr
#define qzero 0
#define qthrow throwException

#define _SHARED_PTR QSharedPointer
#define _SMART_PTR std::unique_ptr

extern unsigned long long download_max;

typedef unsigned __LONG32 qdword;
typedef ULARGE_INTEGER qlarge_int;
typedef WORD qatom;

#define WDCCHAR reinterpret_cast<const wchar_t *>
#define WDCHAR reinterpret_cast<wchar_t *>


typedef QObject qobj;
typedef void qvoid;
typedef bool qbool;
typedef int qint;
typedef unsigned int quint;
typedef unsigned long long qlong;
typedef signed char qschar;
typedef unsigned char qchar;
typedef unsigned short qshort;

typedef unsigned long qulong;

typedef quint64_be qlong_be;
typedef quint64_le qlong_le;
typedef quint32_le quint_le;
typedef quint32_be quint_be;
typedef quint16_be qshort_be;
typedef quint16_le qshort_le;

typedef QBuffer qbuff;
typedef QIODevice qiodev;
typedef QLatin1String ql1str;
typedef QElapsedTimer qtimer;
typedef QByteArray qbyte;
typedef QString qstr;
typedef QStringList qstrl;
typedef QFile qfile;
typedef QFileInfo qfileinfo;
typedef QDir qdir;
typedef QLatin1Char ql1char;
typedef QVector<QVariantList> qVarList;

typedef QVector<qchar> qvec_u8;
typedef QVector<qshort> qvec_u16;
typedef QVector<quint> qvec_uu2;
typedef QVector<qlong> qvec_u64;
typedef QVector<qstrl> qvec_strl;
typedef QVector<qstr> qvec_str;
typedef QVector<QUuid> qvec_guid;

typedef QMultiMap<qshort, qshort> qwordmap;

typedef QMap<qstr, qstr> qMapS;
typedef QVariant qvar;

namespace OPSDefs
{
//Q_NAMESPACE

enum OPSEnums
{
    OPS_EXTARCT_OK = 0,
    OPS_EXTARCT_KEY_INVALID,
    OPS_EXTARCT_SBOX_INVALID,
    OPS_UNSUPPORTED_ENCRYPTION
};
struct OPSKey
{
    QVector<quint> m_hdrkey{};
    QVector<quint> key_pair{};
    QVector<qchar> ops_ievc{};
} __attribute__((__packed__));

struct OPSEntry
{
    qstr m_pname{};
    qstr m_fname{};
    qvar m_offset{};
    qbool m_sparse{0};
    qlong m_length{0};
    qlong m_tmplen{0};
    qbool m_decode{0};
    qsizetype m_index{0};
    qsizetype m_lunid{0};
} __attribute__((__packed__));

#define OPSSBOX \
    "c66363a5c66363a5f87c7c84f87c7c84ee777799ee777799f67b7b8df67b7b8d" \
    "fff2f20dfff2f20dd66b6bbdd66b6bbdde6f6fb1de6f6fb191c5c55491c5c554" \
    "60303050603030500201010302010103ce6767a9ce6767a9562b2b7d562b2b7d" \
    "e7fefe19e7fefe19b5d7d762b5d7d7624dababe64dababe6ec76769aec76769a" \
    "8fcaca458fcaca451f82829d1f82829d89c9c94089c9c940fa7d7d87fa7d7d87" \
    "effafa15effafa15b25959ebb25959eb8e4747c98e4747c9fbf0f00bfbf0f00b" \
    "41adadec41adadecb3d4d467b3d4d4675fa2a2fd5fa2a2fd45afafea45afafea" \
    "239c9cbf239c9cbf53a4a4f753a4a4f7e4727296e47272969bc0c05b9bc0c05b" \
    "75b7b7c275b7b7c2e1fdfd1ce1fdfd1c3d9393ae3d9393ae4c26266a4c26266a" \
    "6c36365a6c36365a7e3f3f417e3f3f41f5f7f702f5f7f70283cccc4f83cccc4f" \
    "6834345c6834345c51a5a5f451a5a5f4d1e5e534d1e5e534f9f1f108f9f1f108" \
    "e2717193e2717193abd8d873abd8d87362313153623131532a15153f2a15153f" \
    "0804040c0804040c95c7c75295c7c75246232365462323659dc3c35e9dc3c35e" \
    "3018182830181828379696a1379696a10a05050f0a05050f2f9a9ab52f9a9ab5" \
    "0e0707090e07070924121236241212361b80809b1b80809bdfe2e23ddfe2e23d" \
    "cdebeb26cdebeb264e2727694e2727697fb2b2cd7fb2b2cdea75759fea75759f" \
    "1209091b1209091b1d83839e1d83839e582c2c74582c2c74341a1a2e341a1a2e" \
    "361b1b2d361b1b2ddc6e6eb2dc6e6eb2b45a5aeeb45a5aee5ba0a0fb5ba0a0fb" \
    "a45252f6a45252f6763b3b4d763b3b4db7d6d661b7d6d6617db3b3ce7db3b3ce" \
    "5229297b5229297bdde3e33edde3e33e5e2f2f715e2f2f711384849713848497" \
    "a65353f5a65353f5b9d1d168b9d1d1680000000000000000c1eded2cc1eded2c" \
    "4020206040202060e3fcfc1fe3fcfc1f79b1b1c879b1b1c8b65b5bedb65b5bed" \
    "d46a6abed46a6abe8dcbcb468dcbcb4667bebed967bebed97239394b7239394b" \
    "944a4ade944a4ade984c4cd4984c4cd4b05858e8b05858e885cfcf4a85cfcf4a" \
    "bbd0d06bbbd0d06bc5efef2ac5efef2a4faaaae54faaaae5edfbfb16edfbfb16" \
    "864343c5864343c59a4d4dd79a4d4dd766333355663333551185859411858594" \
    "8a4545cf8a4545cfe9f9f910e9f9f9100402020604020206fe7f7f81fe7f7f81" \
    "a05050f0a05050f0783c3c44783c3c44259f9fba259f9fba4ba8a8e34ba8a8e3" \
    "a25151f3a25151f35da3a3fe5da3a3fe804040c0804040c0058f8f8a058f8f8a" \
    "3f9292ad3f9292ad219d9dbc219d9dbc7038384870383848f1f5f504f1f5f504" \
    "63bcbcdf63bcbcdf77b6b6c177b6b6c1afdada75afdada754221216342212163" \
    "2010103020101030e5ffff1ae5ffff1afdf3f30efdf3f30ebfd2d26dbfd2d26d" \
    "81cdcd4c81cdcd4c180c0c14180c0c142613133526131335c3ecec2fc3ecec2f" \
    "be5f5fe1be5f5fe1359797a2359797a2884444cc884444cc2e1717392e171739" \
    "93c4c45793c4c45755a7a7f255a7a7f2fc7e7e82fc7e7e827a3d3d477a3d3d47" \
    "c86464acc86464acba5d5de7ba5d5de73219192b3219192be6737395e6737395" \
    "c06060a0c06060a019818198198181989e4f4fd19e4f4fd1a3dcdc7fa3dcdc7f" \
    "4422226644222266542a2a7e542a2a7e3b9090ab3b9090ab0b8888830b888883" \
    "8c4646ca8c4646cac7eeee29c7eeee296bb8b8d36bb8b8d32814143c2814143c" \
    "a7dede79a7dede79bc5e5ee2bc5e5ee2160b0b1d160b0b1daddbdb76addbdb76" \
    "dbe0e03bdbe0e03b6432325664323256743a3a4e743a3a4e140a0a1e140a0a1e" \
    "924949db924949db0c06060a0c06060a4824246c4824246cb85c5ce4b85c5ce4" \
    "9fc2c25d9fc2c25dbdd3d36ebdd3d36e43acacef43acacefc46262a6c46262a6" \
    "399191a8399191a8319595a4319595a4d3e4e437d3e4e437f279798bf279798b" \
    "d5e7e732d5e7e7328bc8c8438bc8c8436e3737596e373759da6d6db7da6d6db7" \
    "018d8d8c018d8d8cb1d5d564b1d5d5649c4e4ed29c4e4ed249a9a9e049a9a9e0" \
    "d86c6cb4d86c6cb4ac5656faac5656faf3f4f407f3f4f407cfeaea25cfeaea25" \
    "ca6565afca6565aff47a7a8ef47a7a8e47aeaee947aeaee91008081810080818" \
    "6fbabad56fbabad5f0787888f07878884a25256f4a25256f5c2e2e725c2e2e72" \
    "381c1c24381c1c2457a6a6f157a6a6f173b4b4c773b4b4c797c6c65197c6c651" \
    "cbe8e823cbe8e823a1dddd7ca1dddd7ce874749ce874749c3e1f1f213e1f1f21" \
    "964b4bdd964b4bdd61bdbddc61bdbddc0d8b8b860d8b8b860f8a8a850f8a8a85" \
    "e0707090e07070907c3e3e427c3e3e4271b5b5c471b5b5c4cc6666aacc6666aa" \
    "904848d8904848d80603030506030305f7f6f601f7f6f6011c0e0e121c0e0e12" \
    "c26161a3c26161a36a35355f6a35355fae5757f9ae5757f969b9b9d069b9b9d0" \
    "178686911786869199c1c15899c1c1583a1d1d273a1d1d27279e9eb9279e9eb9" \
    "d9e1e138d9e1e138ebf8f813ebf8f8132b9898b32b9898b32211113322111133" \
    "d26969bbd26969bba9d9d970a9d9d970078e8e89078e8e89339494a7339494a7" \
    "2d9b9bb62d9b9bb63c1e1e223c1e1e221587879215878792c9e9e920c9e9e920" \
    "87cece4987cece49aa5555ffaa5555ff5028287850282878a5dfdf7aa5dfdf7a" \
    "038c8c8f038c8c8f59a1a1f859a1a1f809898980098989801a0d0d171a0d0d17" \
    "65bfbfda65bfbfdad7e6e631d7e6e631844242c6844242c6d06868b8d06868b8" \
    "824141c3824141c3299999b0299999b05a2d2d775a2d2d771e0f0f111e0f0f11" \
    "7bb0b0cb7bb0b0cba85454fca85454fc6dbbbbd66dbbbbd62c16163a2c16163a"

//Q_ENUM_NS(OPSEnums)

struct OPSDeviceInfo
{
    qstr m_out_path{};
    qbyte m_xml_dev{};
    qiodev *m_ops_dev{};
    qbyte m_tmp_buff{0};
    OPSKey m_ops_key{};
    qsizetype m_blksz{0x200};
    qsizetype m_qc_blksz{0x200};
    QMap<qstr, qstr> m_ops_dl_info{};
    QVector<OPSEntry> m_entries{};
}Q_PACKED;
};

using namespace OPSDefs;
Q_DECLARE_METATYPE(OPSDeviceInfo)

class OPSDecrypt
{
public:
    OPSDecrypt();
    qvoid UnpackOPS(QString ops_path);
    qbool UnpackXML(OPSDeviceInfo &oinfo);
    qbool GetOPSEntries(OPSDeviceInfo &oinfo);
    qbool OPSGetKey(OPSDeviceInfo &oinfo);
    qbool DecOpsData(OPSDeviceInfo &oinfo, qsizetype out_len = {0}, qbool enc = {0});
    qbool DecOpsFile(OPSDeviceInfo &oinfo, OPSEntry entry = {});
public:
   static qbool write_file(qstr path, qbyte data, qbool append);
};
#endif // OPSDECRYPT_H
