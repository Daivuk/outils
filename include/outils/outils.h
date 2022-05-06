#ifndef OUTILS_H_INCLUDED
#define OUTILS_H_INCLUDED

#if defined(WIN32)
#include <Windows.h>
#endif
#include <cinttypes>
#include <string>
#include <vector>

namespace outils
{
    //--------------------------------------
    //--- Strings
    //--------------------------------------

#if defined(WIN32)
    std::wstring utf8ToWide(const std::string& utf8);
    std::string wideToUtf8(const std::wstring& wide);
#endif
    std::vector<std::string> splitString(const std::string& in_string, char in_delimiter, bool in_removeEmptyElements = true);
    std::vector<std::string> splitString(const std::string& in_string, const std::string& in_delimiters);
    std::string removeChars(const std::string& str, const std::string& charsToRemove);
    std::string toUpper(const std::string& str);
    std::string toLower(const std::string& str);
    std::string trim(const std::string& str);

    size_t utf8Length(const std::string& str);
    size_t utf8Pos(const std::string& str, size_t pos);

    //--------------------------------------
    //--- Regex
    //--------------------------------------

    void stripOutComments(std::string& source);
    std::string stripOutComments(const std::string& source);
    void replace(std::string& source, const std::string& reg, const std::string& substitution);
    std::string replace(const std::string& source, const std::string& reg, const std::string& substitution);

    //--------------------------------------
    //--- Files
    //--------------------------------------

    std::string findFile(const std::string& name, const std::string& lookIn = ".", bool deepSearch = true);
    std::vector<std::string> findAllFiles(const std::string& lookIn = ".", const std::string& extension = "*", bool deepSearch = true);
    std::string getPath(const std::string& filename);
    std::string getFilename(const std::string& path);
    std::string getFilenameWithoutExtension(const std::string& path);
    std::string getExtension(const std::string& filename);
    // On Windows, this returns the Roaming App Data path. On other platforms, it returns local directory "./"
    std::string getSavePath(const std::string& appName);
    std::string makeRelativePath(const std::string& path, const std::string& relativeTo);
    std::vector<uint8_t> getFileData(const std::string& filename);
    std::string getFileString(const std::string& filename);
#if defined(WIN32)
    bool fileExists(const std::string& filename);

    struct FileType { std::string typeName; std::string extension; };
    using FileTypes = std::vector<FileType>;

    std::string showOpenDialog(HWND hwndOwner, const std::string& caption, const FileTypes& extensions, const std::string& defaultFilename = "");
    std::string showSaveAsDialog(HWND hwndOwner, const std::string& caption, const FileTypes& extensions, const std::string& defaultFilename = "");
#endif
    std::string showOpenFolderDialog(const std::string& caption, const std::string& defaultPath = "");
    bool createFolder(const std::string& fullPath);
    bool copyFile(const std::string& from, const std::string& to);
    bool createTextFile(const std::string& path, const std::string& content);
    void showInExplorer(const std::string& path);
    void openFile(const std::string& file);

    enum class MessageBoxLevel { Info, Warning, Error, Question };
    enum class MessageBoxType { Ok, OkCancel, YesNo, YesNoCancel };
    enum class MessageBoxReturn : int { CancelNo = 0, OkYes = 1, No = 2 };

    MessageBoxReturn showMessageBox(const std::string& title, const std::string& message, MessageBoxType type = MessageBoxType::Ok, MessageBoxLevel level = MessageBoxLevel::Info);

    //--------------------------------------
    //--- File IO
    //--------------------------------------

    void writeInt8(int8_t val, FILE* pFile);
    void writeUInt8(uint8_t val, FILE* pFile);
    void writeInt16(int16_t val, FILE* pFile);
    void writeUInt16(uint16_t val, FILE* pFile);
    void writeInt32(int32_t val, FILE* pFile);
    void writeUInt32(uint32_t val, FILE* pFile);
    void writeInt64(int64_t val, FILE* pFile);
    void writeUInt64(uint64_t val, FILE* pFile);
    void writeFloat(float val, FILE* pFile);
    void writeDouble(double val, FILE* pFile);
    void writeBool(bool val, FILE* pFile);
    void writeString(const std::string& val, FILE* pFile);
    void writeFloat2(const float* val, FILE* pFile);
    void writeFloat3(const float* val, FILE* pFile);
    void writeFloat4(const float* val, FILE* pFile);
    void writeInt2(const int* val, FILE* pFile);
    void writeInt4(const int* val, FILE* pFile);
    void writeMatrix4x4(const float* val, FILE* pFile);

    int8_t readInt8(FILE* pFile);
    uint8_t readUInt8(FILE* pFile);
    int16_t readInt16(FILE* pFile);
    uint16_t readUInt16(FILE* pFile);
    int32_t readInt32(FILE* pFile);
    uint32_t readUInt32(FILE* pFile);
    float readFloat(FILE* pFile);
    double readDouble(FILE* pFile);
    bool readBool(FILE* pFile);
    std::string readString(FILE* pFile);
    void readFloat2(float* out, FILE* pFile);
    void readFloat3(float* out, FILE* pFile);
    void readFloat4(float* out, FILE* pFile);
    void readInt2(int* out, FILE* pFile);
    void readInt4(int* out, FILE* pFile);
    void readMatrix(float* out, FILE* pFile);

    //--------------------------------------
    //--- Maths
    //--------------------------------------

    const float GOLDEN_RATIO = 1.6180339887498948482f;
    const float GOLDEN_SECOND = 1.0f / 1.6180339887498948482f;
    const float GOLDEN_FIRST = 1.0f - GOLDEN_SECOND;

    const float PI = 3.141592654f;
    const float _2PI = 6.283185307f;
    const float _1DIVPI = 0.318309886f;
    const float _1DIV2PI = 0.159154943f;
    const float PIDIV2 = 1.570796327f;
    const float PIDIV4 = 0.785398163f;

    inline float convertToRad(float fDegrees) { return fDegrees * (PI / 180.0f); }
    inline float convertToDeg(float fRadians) { return fRadians * (180.0f / PI); }

    template<typename Tsize>
    Tsize max(Tsize a, Tsize b)
    {
        return std::max<Tsize>(a, b);
    }
    template<typename Tsize, typename ... Targs>
    Tsize max(Tsize a, Tsize b, Targs ... args)
    {
        return std::max<Tsize>(a, max(b, args...));
    }

    template<typename Tsize>
    Tsize min(Tsize a, Tsize b)
    {
        return std::min<Tsize>(a, b);
    }
    template<typename Tsize, typename ... Targs>
    Tsize min(Tsize a, Tsize b, Targs ... args)
    {
        return std::min<Tsize>(a, min(b, args...));
    }
    
    template<typename T>
    T bezier(const T& p0, const T& p1, const T& p2, const T& p3, float t)
    {
        float invT = 1.0f - t;
        return
            p0 * invT * invT * invT +
            p1 * t * invT * invT * 3.0f +
            p2 * t * t * invT * 3.0f +
            p3 * t * t * t;
    }

    bool lerp(bool from, bool to, float t);
    int lerp(int from, int to, float t);
    unsigned int lerp(unsigned int from, unsigned int to, float t);
    float lerp(float from, float to, float t);
    double lerp(double from, double to, float t);
    std::string lerp(const std::string& from, const std::string& to, float t);

    template<typename T>
    T lerp(const T& from, const T& to, float t)
    {
        return from + t * (to - from);
    }
    
    enum class Tween
    {
        None,
        Linear,
        EaseIn,
        EaseOut,
        EaseBoth,
        BounceIn,
        BounceOut,
        SpringIn,
        SpringOut
    };

    float tween(float t, Tween tween);
    Tween invertTween(Tween tween);

    //--------------------------------------
    //--- Crypto
    //--------------------------------------

    uint32_t hash(const std::string& s, unsigned int seed = 0);

    std::string sha1(const std::string& str);
    std::string md5(const std::string& str);

    bool validateEmail(const std::string& email);

    std::string base64_encode(const uint8_t* buf, unsigned int bufLen);
    std::vector<uint8_t> base64_decode(const std::string& encoded_string);

    //--------------------------------------
    //--- Log
    //--------------------------------------
    enum class LogSeverity { Info, Warning, Error };

    void log(LogSeverity logSeverity, const std::string& message);
    void logInfo(const std::string& message);
    void logWarning(const std::string& message);
    void logError(const std::string& message);
}

#if defined(OUTILS_NO_ASSERTS)
#define OUTILS_FATAL(_msg)
#define OUTILS_ASSERT(_cond, _msg)
#else
#if defined(_DEBUG)
#include <cassert>
#define OUTILS_FATAL(_msg) assert(false && _msg)
#define OUTILS_ASSERT(_cond, _msg) assert((_cond) && _msg)
#else
#include <tinyfiledialogs/tinyfiledialogs.h>
#define OUTILS_FATAL(_msg) \
{ \
    tinyfd_messageBox("ASSERT", _msg, "ok", "error", 1); \
    exit(1); \
}
#define OUTILS_ASSERT(_cond, _msg) \
if (!(_cond)) \
{ \
    tinyfd_messageBox("ASSERT", _msg, "ok", "error", 1); \
    exit(1); \
}
#endif
#endif

#endif /* OUTILS_H_INCLUDED */
