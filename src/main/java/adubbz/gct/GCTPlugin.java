/**
 * Copyright 2023 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted,
 * provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.gct;

import adubbz.gct.action.CreateSourceTypeAction;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@PluginInfo(
        status = PluginStatus.STABLE,
        packageName = CorePluginPackage.NAME,
        category = PluginCategoryNames.CODE_VIEWER,
        shortDescription = "Libclang source parsing",
        description = "Provides libclang-based source code parsing",
        servicesRequired = { DataTypeManagerService.class }
)
public class GCTPlugin extends ProgramPlugin
{
    public static final Logger LOGGER = LogManager.getLogger();

    public GCTPlugin(PluginTool plugintool)
    {
        super(plugintool);
    }
    
    @Override
    protected void init()
    {

    }

    @Override
    protected void programActivated(Program program)
    {
        DataTypeManagerPlugin dtmPlugin = (DataTypeManagerPlugin)(this.tool.getService(DataTypeManagerService.class));

        // Add our custom actions
        this.tool.addLocalAction(dtmPlugin.getProvider(), new CreateSourceTypeAction(program.getDataTypeManager(), dtmPlugin));
    }
}
