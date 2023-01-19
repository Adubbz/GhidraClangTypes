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
package adubbz.gct.processing;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;

import java.util.List;
import java.util.Map;

public class ParsedEnum extends ParsedType
{
    private final String name;
    private final long size;
    private final ImmutableMap<String, Long> values;

    protected ParsedEnum(String name, long size, Map<String, Long> values)
    {
        this.name = name;
        this.size = size;
        this.values = ImmutableMap.copyOf(values);
    }

    @Override
    public DataType createDataType(TypePool pool)
    {
        var enumDataType = new EnumDataType(this.name, (int)this.size);
        this.values.forEach((name, value) -> enumDataType.add(name, value));
        return enumDataType;
    }

    @Override
    public String getName()
    {
        return this.name;
    }

    @Override
    public List<String> getDependencies()
    {
        return ImmutableList.of();
    }
}
