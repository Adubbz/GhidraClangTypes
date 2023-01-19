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
package adubbz.gct.ui;

import adubbz.gct.clang.error.ParseException;
import adubbz.gct.processing.SourceParser;
import adubbz.gct.processing.TypePool;
import docking.DialogComponentProvider;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import java.util.List;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.Document;
import javax.swing.tree.TreePath;
import java.awt.*;

// Based on CreateTypeDefDialog
public class CreateSourceTypeDialog extends DialogComponentProvider
{
    private final DataTypeManager dataTypeManager;
    private final Category category;
    private final SourceParser parser;
    private final TypePool typePool;
    RSyntaxTextArea codeField;
    private boolean isCancelled;

    public CreateSourceTypeDialog(DataTypeManager dataTypeManager, DataTypeManagerPlugin plugin, Category category, TreePath treePath)
    {
        super("Create Types From Source", true, true, true, false);

        this.dataTypeManager = dataTypeManager;
        this.category = category;
        this.parser = new SourceParser();
        this.typePool = new TypePool(dataTypeManager, plugin);

        this.addWorkPanel(this.createPanel());
        this.addOKButton();
        this.addCancelButton();

        // Disable the OK button by default
        this.okButton.setEnabled(false);
    }

    private JPanel createPanel()
    {
        JPanel panel = new JPanel(new BorderLayout());

        this.codeField = new RSyntaxTextArea(20, 60);
        this.codeField.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_CPLUSPLUS);

        Document document = codeField.getDocument();
        document.addDocumentListener(new DocumentListener()
        {
            @Override
            public void insertUpdate(DocumentEvent e) {}

            @Override
            public void removeUpdate(DocumentEvent e) {}

            @Override
            public void changedUpdate(DocumentEvent e)
            {
                okButton.setEnabled(!codeField.getText().isEmpty());
            }
        });

        panel.add(new RTextScrollPane(codeField), BorderLayout.CENTER);

        return panel;
    }

    @Override
    protected void okCallback()
    {
        try
        {
            this.parser.parse(this.typePool, this.codeField.getText());
        }
        catch (ParseException e)
        {
            Msg.error(this, "Failed to parse code", e);
            return;
        }

        TypePool.ResolutionResult result = typePool.resolve();

        if (result.isSuccess())
        {
            List<DataType> dataTypes = ((TypePool.ResolutionResultSuccess) result).getDataTypes();
            int transaction = this.dataTypeManager.startTransaction("Add processed data types");
            dataTypes.forEach(t ->
            {
                var copiedType = t.copy(this.dataTypeManager);
                try
                {
                    copiedType.setCategoryPath(this.category.getCategoryPath());
                    this.dataTypeManager.addDataType(copiedType, TypePool.REPLACE_EMPTY_STRUCTS_OR_KEEP_HANDLER);
                }
                catch (DuplicateNameException e) {}
            });
            this.dataTypeManager.endTransaction(transaction, true);
        }
        else if (result instanceof TypePool.ResolutionResultUnresolvedDependencies)
        {
            Msg.error(this, "Unable to locate required types: " + ((TypePool.ResolutionResultUnresolvedDependencies)result).getDependencies());
            return;
        }

        this.close();
    }

    @Override
    protected void cancelCallback()
    {
        super.cancelCallback();
        isCancelled = true;
    }

    public boolean isCancelled()
    {
        return isCancelled;
    }
}

