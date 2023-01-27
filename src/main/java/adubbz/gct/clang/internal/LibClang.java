/**
 * Copyright 2023 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted,
 * provided that the above copyright notice and this permission notice appear in all copies.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.gct.clang.internal;

import adubbz.gct.clang.Cursor;
import adubbz.gct.clang.CursorKind;
import adubbz.gct.clang.TypeKind;
import adubbz.gct.clang.UnsavedFile;
import adubbz.gct.clang.internal.pointer.DiagnosticPointer;
import adubbz.gct.clang.internal.pointer.IndexPointer;
import adubbz.gct.clang.internal.pointer.TranslationUnitPointer;
import com.sun.jna.*;
import com.sun.jna.platform.EnumConverter;

import java.util.Collections;

public interface LibClang extends Library
{
    String OS_NAME = System.getProperty("os.name").toLowerCase();
    TypeMapper TYPE_MAPPER = createTypeMapper();
    LibClang INSTANCE = (LibClang) Native.load(getClangPath(), LibClang.class, Collections.singletonMap(Library.OPTION_TYPE_MAPPER, TYPE_MAPPER));

    // https://github.com/llvm/llvm-project/blob/main/clang/include/clang-c/CXString.h

    /* L50 */ String clang_getCString(CXString.ByValue string);

    /* L55 */ void clang_disposeString(CXString.ByValue string);

    // https://github.com/llvm/llvm-project/blob/main/clang/include/clang-c/CXDiagnostic.h

    /* L239 */ CXString.ByValue clang_formatDiagnostic(DiagnosticPointer diagnostic, int options);

    /* L249 */ int clang_defaultDiagnosticDisplayOptions();

    // https://github.com/llvm/llvm-project/blob/main/clang/include/clang-c/Index.h
    // as at https://github.com/llvm/llvm-project/blob/95a4c0c83554c025ef709a6805e67233d0dedba0/clang/include/clang-c/Index.h
    /* L154 */ void clang_disposeDiagnostic(DiagnosticPointer diagnostic);

    /* L267 */ IndexPointer clang_createIndex(boolean excludeDeclarationsFromPCH, boolean displayDiagnostics);

    /* L276 */ void clang_disposeIndex(IndexPointer index);

    /* L419 */ int clang_getNumDiagnostics(TranslationUnitPointer tu);

    /* L430 */ DiagnosticPointer clang_getDiagnostic(TranslationUnitPointer tu, int index);

    /* L700 */ int clang_parseTranslationUnit2(IndexPointer index, String sourceFilename, String[] commandLineArgs, int numCommandLineArgs, UnsavedFile[] unsavedFiles, int numUnsavedFiles, int options, TranslationUnitPointer[] outTU);

    /* L790 */ int clang_defaultSaveOptions(TranslationUnitPointer tu);

    /* L850 */ int clang_saveTranslationUnit(TranslationUnitPointer tu, String filename, int options);

    /* L866 */ void clang_disposeTranslationUnit(TranslationUnitPointer tu);

    /* L2130 */ CXCursor.ByValue clang_getTranslationUnitCursor(TranslationUnitPointer tu);

    /* L2150 */ CursorKind clang_getCursorKind(CXCursor.ByValue cursor);

    /* L2155 */ boolean clang_isDeclaration(CursorKind kind);

    /* L2843 */ CXType.ByValue clang_getCursorType(CXCursor.ByValue cursor);

    /* L2851 */ CXString.ByValue clang_getTypeSpelling(CXType.ByValue type);

    /* L2859 */ CXType.ByValue clang_getTypedefDeclUnderlyingType(CXCursor.ByValue cursor);

    /* L2867 */ CXType.ByValue clang_getEnumDeclIntegerType(CXCursor.ByValue cursor);

    /* 2877 */ long clang_getEnumConstantDeclValue(CXCursor.ByValue cursor);

    /* L2888 */ long clang_getEnumConstantDeclUnsignedValue(CXCursor.ByValue cursor);

    /* L3101 */ CXString.ByValue clang_getTypedefName(CXType.ByValue type);

    /* L3159 */ CXCursor.ByValue clang_getTypeDeclaration(CXType.ByValue type);

    /* L3425 */ long clang_Type_getSizeOf(CXType.ByValue type);

    /* L3697 */ Cursor.ChildVisitResult clang_visitChildren(CXCursor.ByValue parent, CXCursorVisitor visitor, Pointer clientData);

    /* L3792 */ CXString.ByValue clang_getCursorSpelling(CXCursor.ByValue cursor);

    /* L3899 */ CXString.ByValue clang_getCursorDisplayName(CXCursor.ByValue cursor);

    private static boolean isWindows()
    {
        return OS_NAME.contains("win");
    }

    private static boolean isMac()
    {
        return OS_NAME.contains("mac");
    }

    private static String getClangPath()
    {
        if (isWindows())
            return "libclang";

        // Use Xcode's clang to spare having multiple several-hundred-MB files
        if (isMac())
            return "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/libclang.dylib";

        return "clang";
    }

    private static TypeMapper createTypeMapper()
    {
        var mapper = new DefaultTypeMapper();
        mapper.addTypeConverter(Cursor.ChildVisitResult.class, new EnumConverter<>(Cursor.ChildVisitResult.class));
        mapper.addTypeConverter(CursorKind.class, new IntegerTypeConverter<>(CursorKind::fromInteger, CursorKind::getValue));
        mapper.addTypeConverter(TypeKind.class, new IntegerTypeConverter<>(TypeKind::fromInteger, TypeKind::getValue));
        return mapper;
    }

    interface CXCursorVisitor extends Callback
    {
        Cursor.ChildVisitResult invoke(CXCursor.ByValue cursor, CXCursor.ByValue parent, Pointer clientData);
    }

    class IntegerTypeConverter<T> implements TypeConverter
    {
        private final java.util.function.Function<Integer, T> from;
        private final java.util.function.Function<T, Integer> to;

        private IntegerTypeConverter(java.util.function.Function<Integer, T> from, java.util.function.Function<T, Integer> to)
        {
            this.from = from;
            this.to = to;
        }

        @Override
        public Object fromNative(Object o, FromNativeContext fromNativeContext)
        {
            return this.from.apply((Integer)o);
        }

        @Override
        public Object toNative(Object o, ToNativeContext toNativeContext)
        {
            return this.to.apply((T)o);
        }

        @Override
        public Class<?> nativeType()
        {
            return Integer.class;
        }
    }
}
