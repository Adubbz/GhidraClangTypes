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
package adubbz.gct.action;

import javax.swing.tree.TreePath;

import adubbz.gct.ui.CreateSourceTypeDialog;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.BuiltInArchiveNode;
import ghidra.app.plugin.core.datamgr.tree.CategoryNode;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataTypeManager;

public class CreateSourceTypeAction extends DockingAction
{
    private final DataTypeManager dataTypeManager;
    private final DataTypeManagerPlugin plugin;

    public CreateSourceTypeAction(DataTypeManager dataTypeManager, DataTypeManagerPlugin plugin)
    {
        super("New Types From Source", plugin.getName());
        this.dataTypeManager = dataTypeManager;
        this.plugin = plugin;

        this.setPopupMenuData(new MenuData(new String[] { "New Types From Source" }, "Create"));
    }

    @Override
    public boolean isEnabledForContext(ActionContext context)
    {
        CategoryNode categoryNode = this.getCategoryNode(context);
        if (categoryNode instanceof BuiltInArchiveNode) {
            return false;
        }
        return categoryNode != null && categoryNode.isModifiable();
    }

    @Override
    public void actionPerformed(ActionContext context)
    {
        CategoryNode categoryNode = getCategoryNode(context);
        Category category = categoryNode.getCategory();
        CreateSourceTypeDialog dialog = new CreateSourceTypeDialog(this.dataTypeManager, this.plugin, category, categoryNode.getTreePath());
        this.plugin.getTool().showDialog(dialog);

        if (dialog.isCancelled()) {
            return;
        }
    }

    private CategoryNode getCategoryNode(ActionContext context)
    {
        if (!(context instanceof DataTypesActionContext)) {
            return null;
        }

        Object contextObject = context.getContextObject();
        GTree gtree = (GTree) contextObject;

        TreePath[] selectionPaths = gtree.getSelectionPaths();
        if (selectionPaths.length != 1) {
            return null;
        }

        GTreeNode node = (GTreeNode)selectionPaths[0].getLastPathComponent();
        return getCategoryForNode(node);
    }

    private CategoryNode getCategoryForNode(GTreeNode node)
    {
        while (!(node instanceof CategoryNode) && node != null) {
            node = node.getParent();
        }
        return (CategoryNode)node;
    }
}

