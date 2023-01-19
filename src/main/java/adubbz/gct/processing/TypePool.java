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
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.*;
import ghidra.util.data.DataTypeParser;

import java.util.*;

public class TypePool
{
    private final DataTypeManager dataTypeManager;
    private final DataTypeManagerService dataTypeManagerService;

    private Map<String, ParsedType> parsedTypes = new HashMap<>();
    private DataTypeManager dtm ;
    private DataTypeParser typeParser;

    public TypePool(DataTypeManager dataTypeManager, DataTypeManagerService dataTypeManagerService)
    {
        this.dataTypeManager = dataTypeManager;
        this.dataTypeManagerService = dataTypeManagerService;

        this.dtm = new StandAloneDataTypeManager(CategoryPath.ROOT.getName());
        this.typeParser = new DataTypeParser(this.dtm, this.dtm, this.dataTypeManagerService, DataTypeParser.AllowedDataTypes.FIXED_LENGTH);
    }

    public ResolutionResult resolve()
    {
        int transaction = this.dtm.startTransaction("Process clang types");

        // Add IDA types that aren't included by default
        this.addTypedef("long long[2]", "__int128");
        this.addTypedef("unsigned long long[2]", "__uint128");
        this.addTypedef("unsigned long long[2]", "unsigned __int128");

        Set<ParsedType> outstandingParsedTypes = Sets.newHashSet(this.parsedTypes.values());

        // Iteratively create data types as their dependencies are fulfilled
        while (!outstandingParsedTypes.isEmpty())
        {
            boolean hasResolved = false;

            for (var it = outstandingParsedTypes.iterator(); it.hasNext();)
            {
                var parsedType = it.next();

                if (this.checkDependenciesFulfilled(parsedType))
                {
                    var dt = parsedType.createDataType(this);
                    this.dtm.addDataType(dt, REPLACE_EMPTY_STRUCTS_OR_KEEP_HANDLER);
                    it.remove();
                    hasResolved = true;
                }
            }

            // Failed to resolve any parsed types
            if (!hasResolved)
            {
                Set<String> unresolvedDependencies = outstandingParsedTypes.stream().flatMap(parsedType -> this.getUnfulfilledDependencies(parsedType).stream()).collect(ImmutableSet.toImmutableSet());
                this.dtm.endTransaction(transaction, false);
                return new ResolutionResultUnresolvedDependencies(unresolvedDependencies);
            }
        }

        this.dtm.endTransaction(transaction, true);

        List<DataType> allTypes = new ArrayList<>();
        this.dtm.getAllDataTypes(allTypes);
        return new ResolutionResultSuccess(ImmutableList.copyOf(allTypes));
    }

    public void addParsedType(ParsedType type)
    {
        this.parsedTypes.put(type.getName(), type);
    }

    public void clearParsedTypes()
    {
        this.parsedTypes.clear();
    }

    public DataType getType(String name)
    {
        try
        {
            return typeParser.parse(name);
        }
        catch (Exception e)
        {
            return null;
        }
    }

    private void addTypedef(String from, String to)
    {
        this.dtm.addDataType(new TypedefDataType(to, this.getType(from)), REPLACE_EMPTY_STRUCTS_OR_KEEP_HANDLER);
    }

    private boolean hasType(String name)
    {
        return this.getType(name) != null;
    }

    private boolean checkDependenciesFulfilled(ParsedType type)
    {
        for (var dependency : type.getDependencies())
        {
            if (!this.hasType(dependency))
                return false;
        }

        return true;
    }

    private List<String> getUnfulfilledDependencies(ParsedType type)
    {
        return type.getDependencies().stream().filter(s -> !this.hasType(s)).toList();
    }

    public static abstract class ResolutionResult
    {
        public final boolean isSuccess()
        {
            return this instanceof ResolutionResultSuccess;
        }
    }

    public static class ResolutionResultUnresolvedDependencies extends ResolutionResult
    {
        private final Set<String> dependencies;

        private ResolutionResultUnresolvedDependencies(Set<String> dependencies)
        {
            this.dependencies = dependencies;
        }

        public ImmutableSet<String> getDependencies()
        {
            return ImmutableSet.copyOf(this.dependencies);
        }
    }

    public static class ResolutionResultSuccess extends ResolutionResult
    {
        private final ImmutableList<DataType> dataTypes;

        private ResolutionResultSuccess(ImmutableList<DataType> dataTypes)
        {
            this.dataTypes = dataTypes;
        }

        public List<DataType> getDataTypes()
        {
            return this.dataTypes;
        }
    }

    public final static DataTypeConflictHandler REPLACE_EMPTY_STRUCTS_OR_KEEP_HANDLER =
        new DataTypeConflictHandler()
        {
            private ConflictResult resolveConflictReplaceEmpty(DataType addedDataType, DataType existingDataType)
            {
                if (existingDataType.isNotYetDefined()) {
                    return ConflictResult.REPLACE_EXISTING;
                }
                return ConflictResult.USE_EXISTING;
            }

            @Override
            public ConflictResult resolveConflict(DataType addedDataType, DataType existingDataType)
            {
                if (addedDataType instanceof Structure) {
                    if (existingDataType instanceof Structure) {
                        return resolveConflictReplaceEmpty(addedDataType, existingDataType);
                    }
                }
                else if (addedDataType instanceof Union) {
                    if (existingDataType instanceof Union) {
                        return resolveConflictReplaceEmpty(addedDataType, existingDataType);
                    }
                }
                return ConflictResult.USE_EXISTING;
            }

            @Override
            public boolean shouldUpdate(DataType sourceDataType, DataType localDataType) {
                return false;
            }

            @Override
            public DataTypeConflictHandler getSubsequentHandler() {
                return this;
            }
        };
}
