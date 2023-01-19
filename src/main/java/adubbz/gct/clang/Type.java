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
package adubbz.gct.clang;

import adubbz.gct.clang.internal.CXType;
import adubbz.gct.clang.internal.LibClang;
import com.google.common.base.Preconditions;
import jnr.posix.LibC;

public class Type
{
    private final CXType.ByValue self;

    protected Type(CXType.ByValue self)
    {
        Preconditions.checkNotNull(self);
        this.self = self;
    }

    /**
     * Returns the typedef name of the given type.
     */
    public String getTypedefName()
    {
        return LibClang.INSTANCE.clang_getTypedefName(this.self).toString();
    }

    /**
     * Return the kind of this type.
     */
    public TypeKind kind()
    {
        return TypeKind.fromInteger(this.self.kind);
    }

    /**
     * Return the cursor for the declaration of the given type.
     */
    public Cursor getDeclaration()
    {
        return new Cursor(LibClang.INSTANCE.clang_getTypeDeclaration(this.self));
    }

    /**
     * Retrieve the size of the record.
     */
    public long getSize()
    {
        return LibClang.INSTANCE.clang_Type_getSizeOf(this.self);
    }

    /**
     * Retrieve the spelling of this Type.
     */
    public String spelling()
    {
        return LibClang.INSTANCE.clang_getTypeSpelling(this.self).toString();
    }
}
