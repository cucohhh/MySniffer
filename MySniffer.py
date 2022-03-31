#-------------------------------------------------------------------------------
# Name:        MySniffer.py
#
# Author:      Gardenia22
#
# Created:     10/21/2014
# Copyright:   (c) Gardenia22 2014
#
#-------------------------------------------------------------------------------

import wx
import wx.lib.mixins.listctrl
import sys, glob, random
from importlib import reload

import data
from Pmodules import *
import os
import matplotlib
#import numpy as np
import json
matplotlib.use('WXAgg')
from matplotlib.figure import Figure
from matplotlib.backends.backend_wxagg import \
    FigureCanvasWxAgg as FigCanvas, \
    NavigationToolbar2WxAgg as NavigationToolbar
import wx.html

class PsMain(wx.Frame, wx.lib.mixins.listctrl.ColumnSorterMixin):
    def __init__(self, parent, title):
        wx.Frame.__init__(self, parent, title = title,size=(800,768))
        self.run = False
        self.devs = [] #devices to capture packets 网卡接口设备
        self.filters = "" #filters 过滤器
        self.captureThread = [] ## 捕获线程
        self.packetCounts = 0  ## 包数量
        self.packets = [] ##数据包
        self.analysis_packets =[]
        self.packetHeads = [] ##包头
        self.filename = "" # Filename to save
        self.protocolStats = {} # protocol stats ## 协议统计数据
        self.sourceStats = {} ## 源 统计数据
        self.destinationStats = {} ## 目的地址 统计数据
        self.ipCounts = 0 ## IP地址数量
        self.CreateStatusBar() # A Statusbar in the bottom ？of the window 状态栏
        toolbar = self.CreateToolBar() ##工具栏
        
        
        ## Setting up the menu. ## 设置菜单栏
        filemenu = wx.Menu()
        capturemenu = wx.Menu()
        statsmenu = wx.Menu()
        toolmenu = wx.Menu()
        helpmenu = wx.Menu()

        ## wx.ID_ABOUT and wx.ID_EXIT are standard IDs provided by wxWidgets.
        menuSave = filemenu.Append(wx.ID_SAVE, "&Save", " Save captured packet bytes and analyzed information")
        menuSaveAs = filemenu.Append(wx.ID_SAVEAS, "&Save As", "Save packet bytes and analyzed information as another file")
        filemenu.AppendSeparator()
        menuExit = filemenu.Append(wx.ID_EXIT,"&Exit"," Terminate the program")

        menuInterfaces = capturemenu.Append(wx.ID_ANY, "&Interfaces"," Show all the open interfaces")
        menuStart = capturemenu.Append(wx.ID_ANY, "&Start"," Start capturing packets")
        menuStop = capturemenu.Append(wx.ID_ANY, "&Stop"," Stop capturing packets")
        menuFilters = capturemenu.Append(wx.ID_ANY, "&Filters", " set the filter for capturing packets")
        
        menuProtocol = statsmenu.Append(wx.ID_ANY, "&Protocol", " see the packets protocol stats of current capturing")
        menuIP = statsmenu.Append(wx.ID_ANY, "&IP", " see the IP stats of current capturing")

        #menuExtract = toolmenu.Append(wx.ID_ANY, "&Extract File", " extract files among packets")

        menuContent = helpmenu.Append(wx.ID_HELP_CONTENTS, "&Content", " look up help content")
        menuAbout = helpmenu.Append(wx.ID_ABOUT, "&About", " Information about this program")

        ## Creating the menubar.
        menuBar = wx.MenuBar()
        menuBar.Append(filemenu,"&File") # Adding the "filemenu" to the MenuBar
        menuBar.Append(capturemenu,"&Capture")
        menuBar.Append(statsmenu,"&Stats")
        #menuBar.Append(toolmenu,"Tool")
        menuBar.Append(helpmenu,"&Help")

        ## bind menu event
        self.Bind(wx.EVT_MENU, self.OnExit, menuExit)
        self.Bind(wx.EVT_MENU, self.OnInterfaces, menuInterfaces)
        self.Bind(wx.EVT_MENU, self.OnFilters, menuFilters)
        self.Bind(wx.EVT_MENU, self.OnStart, menuStart)
        self.Bind(wx.EVT_MENU, self.OnStop, menuStop)
        self.Bind(wx.EVT_MENU, self.OnSave, menuSave)
        self.Bind(wx.EVT_MENU, self.OnSaveAs, menuSaveAs)
        self.Bind(wx.EVT_MENU, self.OnProtocol, menuProtocol)
        self.Bind(wx.EVT_MENU, self.OnIP, menuIP)
        self.Bind(wx.EVT_MENU, self.OnContent, menuContent)
        self.Bind(wx.EVT_MENU, self.OnAbout, menuAbout)
        self.SetMenuBar(menuBar)  # Adding the MenuBar to the Frame content.

        '''
        il = wx.ImageList(16,16, True)
        # add some arrows for the column sorter
        self.up = il.AddWithColourMask(
            wx.Bitmap("sm_up.bmp", wx.BITMAP_TYPE_BMP), "blue")
        self.dn = il.AddWithColourMask(
            wx.Bitmap("sm_down.bmp", wx.BITMAP_TYPE_BMP), "blue")
        '''
        ##create tool bar 创建工具栏

        ## creat start tool
        bmp = wx.Image("start.bmp", wx.BITMAP_TYPE_BMP).ConvertToBitmap()
        toolStart = toolbar.AddSimpleTool(-1, bmp, "start", "start capture packets")
        self.Bind(wx.EVT_MENU, self.OnStart, toolStart)
        
        ## creat stop tool
        bmp = wx.Image("stop.bmp", wx.BITMAP_TYPE_BMP).ConvertToBitmap()
        toolStop = toolbar.AddSimpleTool(-1, bmp, "stop", "stop capture packets")
        self.Bind(wx.EVT_MENU, self.OnStop, toolStop)
        
        ## creat save tool
        bmp = wx.Image("save.bmp", wx.BITMAP_TYPE_BMP).ConvertToBitmap()
        toolSave = toolbar.AddSimpleTool(-1, bmp, "save", "save captured packet bytes and analyzed information")
        self.Bind(wx.EVT_MENU, self.OnSave, toolSave)
        
        ##creat filter tool
        bmp = wx.Image("filters.bmp", wx.BITMAP_TYPE_BMP).ConvertToBitmap()
        toolFilters = toolbar.AddSimpleTool(-1, bmp, "filters", "set the filter for capturing packets")
        self.Bind(wx.EVT_MENU, self.OnFilters, toolFilters)
        toolbar.Realize()        
        
        ## create the list control
        self.list = wx.ListCtrl(self, -1, style=wx.LC_REPORT|wx.LC_HRULES|wx.LC_SINGLE_SEL)


        ## add some columns
        for col, text in enumerate(data.columns):
            self.list.InsertColumn(col, text)
            self.list.SetColumnWidth(col, 130)#set the width of columns
            self.list.SetColumnWidth(5,700)

        self.itemDataMap = {}
        ## initialize the column sorter
        wx.lib.mixins.listctrl.ColumnSorterMixin.__init__(self,
                                                          len(data.columns))
        self.Bind(wx.EVT_LIST_ITEM_SELECTED, self.OnPacketListSelect, self.list)

        ## create tree display
        self.tree = wx.TreeCtrl(self,-1)

        self.root = self.tree.AddRoot("Frame Information")

        #self.AddTreeNodes(self.root, data.tree)

        self.tree.Expand(self.root)

        self.html1 = wx.html.HtmlWindow(self)
        self.html1.SetPage("""<font face="Calibri" size="4">Packet Bytes</font>""")

        #self.html1.SetPage(data.page)
        
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.sizertext = wx.BoxSizer(wx.HORIZONTAL)
        self.sizertext.Add(self.html1,5,wx.EXPAND)

        boaderstyle = 5
        self.sizer.Add(self.list, 4, wx.EXPAND, boaderstyle)
        self.sizer.Add(self.tree, 2, wx.EXPAND, boaderstyle)
        self.sizer.Add(self.sizertext, 2, wx.EXPAND, boaderstyle)
        self.SetSizer(self.sizer)
        self.Show(True)

    def GetListCtrl(self):
        return self.list
    '''
    def GetSortImages(self):
        return (self.dn, self.up)
    '''
    def AddTreeNodes(self, parentItem, items):
        """
        Recursively traverses the data structure, adding tree nodes to
        match it.
        """
        newItem = self.tree.AppendItem(parentItem, items[0])
        #print items[1]
        for key in items[1]:
            self.tree.AppendItem(newItem, "%s: %s" % (key,str(items[1][key])))
        self.tree.Expand(newItem)

    def OnExit(self,e):
        self.Close(True)  # Close the frame.

    def OnInterfaces(self,e):
        self.frameInterface = wx.Frame(self, -1, title = "Interfaces")
        panel = wx.Panel(self.frameInterface,-1)
        sizerInterface = wx.BoxSizer(wx.VERTICAL)
        
        i = 0
        self.checkBox = []
        I = Interfaces()
        if len(I)>0:
            for item in I:
                self.checkBox.append(wx.CheckBox(panel, -1, item))
                sizerInterface.Add(self.checkBox[i],1,wx.EXPAND)
                i += 1
                print("############")
                print(i)
        else:
            wx.MessageBox("Can't find network devices, you may need administrator privileges.", "Message",wx.OK)
        for item in self.devs:
            self.checkBox[item-1].SetValue(1)
        buttonInterface = wx.Button(panel, label = 'OK')
        self.Bind(wx.EVT_BUTTON, self.OnButtonInterface, buttonInterface)
        sizerInterface.Add(buttonInterface,0, wx.ALIGN_CENTER|wx.ALL, 10)
        panel.SetSizer(sizerInterface)
        self.frameInterface.Show(True)
    #def OnCheckbox(self,e):

    def OnButtonInterface(self,e):
        i = 1
        self.devs = []
        for checkBox in self.checkBox:
            if checkBox.IsChecked():
                print ("%d checked" % i)
                self.devs.append(i)
            else:
                print ("%d unchecked" % i)
            i += 1
        self.frameInterface.Destroy()
        #Captures(self,devs)
    def AddListItem(self,item):
        #index = self.list.InsertStringItem(sys.maxint, str(item[0]))
        item_id = random.randint(0,100)
        index = self.list.InsertItem(item_id, str(item[0]))
        if self.packetCounts==1:
            #print "set default row"
            self.firstRow = index
        for col, text in enumerate(item[1:]):
            #print col, text
            self.list.SetItem(index, col+1, str(text))
            self.list.SetItemData(index, index)
            self.itemDataMap[index] = item
            #self.itemDataMap[index] = self.packetCounts
    def PacketCount(self):
        self.packetCounts += 1
        return self.packetCounts

    ## 创建过滤器选择窗口
    def OnFilters(self,e):
        self.frameFilters = wx.Frame(self, -1, title = "Filters")
        panel = wx.Panel(self.frameFilters,-1)
        sizerFilters = wx.BoxSizer(wx.HORIZONTAL)
        sizerButtons = wx.BoxSizer(wx.VERTICAL)
        Filterlist = wx.ListCtrl(panel, -1, style=wx.LC_LIST|wx.LC_SINGLE_SEL) ## 列表模式 单一选择 ListCtrl 多行列表
        ##Filterlist = wx.ListCtrl(panel, -1, style=wx.LC_LIST)
        Filterlist.SetColumnWidth(0, wx.LIST_AUTOSIZE)
        ## add filter options
        for name, value in data.filters:
            #item = Filterlist.InsertStringItem(sys.maxsize,name)
            i=100
            #item = Filterlist.InsertStringItem(i, name)
            item = Filterlist.InsertItem(i, name)
            i=i+1
            if value == self.filters:
                ## 设置被选择过滤器状态
                Filterlist.SetItemState(item, wx.LIST_STATE_SELECTED, wx.LIST_STATE_SELECTED)
                print (Filterlist.GetItemState(item,wx.LIST_STATE_SELECTED))
        
        buttonFiltersOK = wx.Button(panel, label = 'OK')
        buttonFiltersCANCEL = wx.Button(panel, label = 'CANCEL')


        self.Bind(wx.EVT_LIST_ITEM_SELECTED, self.OnFilterListSelect, Filterlist)

        self.Bind(wx.EVT_BUTTON, self.OnButtonOKFilter, buttonFiltersOK)
        self.Bind(wx.EVT_BUTTON, self.OnButtonCANCELFilter, buttonFiltersCANCEL)

        sizerButtons.Add(buttonFiltersOK ,0, wx.ALIGN_CENTER|wx.ALL, 5)
        sizerButtons.Add(buttonFiltersCANCEL, 0, wx.ALIGN_CENTER|wx.ALL, 5)
        sizerFilters.Add(Filterlist,1,wx.EXPAND)
        sizerFilters.Add(sizerButtons,1,wx.ALIGN_CENTER|wx.ALL)
        panel.SetSizer(sizerFilters)
        self.frameFilters.Show(True)

    ## 设置filters 根据选择时间 ，选择对应的编号
    def OnFilterListSelect(self,e):
        i = e.GetIndex()
        print("被选择过滤器编号:")
        print(i)
        #print "Item selected:", i
        self.filtersChoice = data.filters[i][1]
        print("被选择的过滤器内容：")
        print(self.filtersChoice)
        #print self.filters
    def OnButtonOKFilter(self,e):
        self.frameFilters.Destroy()
        self.filters = self.filtersChoice
        print ("filters = %s",self.filters)

    def OnButtonCANCELFilter(self,e):
        self.frameFilters.Destroy()

    def OnStop(self,e):
        for t in self.captureThread:
            t.stop()
        if self.packetCounts>0:
            self.list.SetItemState(self.firstRow, wx.LIST_STATE_SELECTED, wx.LIST_STATE_SELECTED)
            wx.MessageBox("Packets capturing stoped.", "Message",wx.OK)
        self.run = False
    def CreateFlowWin(self,flow_list):
        self.frameFlowWin = wx.Frame(self,-1,title = "TraceFlow",size=(600,600))
        panel = wx.Panel(self.frameFlowWin,-1)
        ##flow_str = "<text>test data send<br><br>  <br><br><br><br>test data recieve </text>"
        flow_str = "<text>send data</text><br>"+"<p style=‘width:10px’><font color='blue'>"+flow_list[0]+"</font><br><br></p>"+"<text>receive data</text><br>"+"<font color='red'>"+flow_list[1]+"</font>"
        flowHtml = wx.html.HtmlWindow(panel)
        flowHtml.SetPage(flow_str)
        sizerFlowWin = wx.BoxSizer(wx.HORIZONTAL)
        sizerFlowWin.Add(flowHtml,1,wx.EXPAND)
        panel.SetSizer(sizerFlowWin)
        self.frameFlowWin.Show(True)

    def trackFlow(self,selected_packets,flow_str):

        print(selected_packets)
        s=" "
        for selected in selected_packets[4]:
            if selected >32 and selected <127:
                s += chr(selected)
            else:
                s +="."
        print("selected str")
        print(s)

        ## 寻找 源IP　目的IP 源 端口号 目的端口号 一样的 数据包  并转换成字符串表示
        for pkt in self.analysis_packets:

            if pkt[0]== selected_packets[0] and pkt[1] == selected_packets[1] and\
                    pkt[2] == selected_packets[2] and pkt[3] ==selected_packets[3]:
                pkt_data1 = pkt[4][54:]
                index1 = 0
                for s in pkt_data1:
                    index1 = index1+1
                    if index1 % 100 == 0:
                        flow_str[0] +="<br>"
                    if s > 32 and s < 127:
                        flow_str[0] += chr(s)
                    else:
                        flow_str[0] += "."
                flow_str[0] += "<br>"
        ## 追踪返回的 tcp流  源IP、端口 和 目的IP、端口颠倒
        for pkt in self.analysis_packets:

            if pkt[1]== selected_packets[0] and pkt[0] == selected_packets[1] and\
                    pkt[3] == selected_packets[2] and pkt[2] ==selected_packets[3]:
                pkt_data2 = pkt[4][54:]
                for s in pkt_data2:

                    if s > 32 and s < 127:
                        flow_str[1] += chr(s)
                    else:
                        flow_str[1] += "."
                flow_str[1] += "<br>"
        #print("#### send_str"+send_str)
        return flow_str


    def OnPacketListSelect(self,e):
        ilist = e.GetIndex()
        print("##### ilist")
        print(ilist)
        i = self.list.GetItemData(ilist)
        print("###### packet which is selected######")
        print(self.packets[i])
        print(self.analysis_packets[i])
        flow_string=["",""]
        test_str = self.trackFlow(self.analysis_packets[i],flow_string)
        print("#####send"+test_str[0])
        print("####recieve"+test_str[1])

        ## 创建追踪流窗口
        self.CreateFlowWin(flow_string)

        page = """<html><font face="Courier New" size="2"><table><tr>"""
        s1 = ""
        for index in range(len(self.packets[i])):
            if index % 16 == 0:
                page += "<td>%s</td></tr><tr><td>%.4x</td><td>" % (s1,index%16)
                s1 = ""
            else:
                if index % 8 == 0:
                    page += "</td><td>"
                    s1 +="</td><td>"
            byte = self.packets[i][index]
            page += "%.2x " % byte
            if byte>32 and byte <127:
                s1 += chr(byte)
            else:
                s1 += "."
            #print s1
        if ((len(self.packets[i])-1) % 16) < 8:
            page+="</td><td>"
            
        page += "</td><td>%s</td></tr></table></font></html>" % s1
        #print page
        self.html1.SetPage(page)
        ## add tree information
        self.tree.Delete(self.root)
        self.root = self.tree.AddRoot("Head Information")
        for item in self.packetHeads[i]:
            #root = self.tree.AddRoot(item[0])
            self.AddTreeNodes(self.root, item)
        self.tree.Expand(self.root)

    def OnStart(self,e):
        if self.run:
            return 0
        if len(self.devs)==0:
            wx.MessageBox("Please selecte interface first.", "Message",wx.OK)
        for d in self.devs:
            self.run = True
            thread = Captures(self,d)
            self.captureThread.append(thread)
            thread.start()
    def SaveFile(self):
        if self.filename:
            out = []
            for i in range(0,self.packetCounts):
                out.append({"Bytes":self.packets[i],"Heads":self.packetHeads[i]})
            f = open(self.filename, 'w')
            try:
                print >> f,json.dumps(out,indent=4)
                wx.MessageBox("Saved in %s." % self.filename, "Message",wx.OK)
            except:
                wx.MessageBox("Save failed.", "Message",wx.OK)
            f.close()
    def OnSave(self, e,):
        if not self.filename:
            self.OnSaveAs(e)
        else:
            self.SaveFile()

    def OnSaveAs(self, e):
        dlg = wx.FileDialog(self, "Save packets as...", os.getcwd(),
                           style=wx.SAVE | wx.OVERWRITE_PROMPT)
        if dlg.ShowModal() == wx.ID_OK:
            filename = dlg.GetPath()
            if not os.path.splitext(filename)[1]:
                filename = filename + '.json'
            self.filename = filename
            self.SaveFile()
            #self.SetTitle(self.title + ' -- ' + self.filename)
        dlg.Destroy()
    def OnProtocol(self,e):
        protocol = []
        counts = []
        details = "\n\nTotal Counts: %d\n" % self.packetCounts
        for p in self.protocolStats:
            details += "%s: %d %.2f%%\n" % (
                p, self.protocolStats[p], float(self.protocolStats[p])*100/self.packetCounts)
            if p in data.abbr:
                protocol.append(data.abbr[p])
            else:
                protocol.append(p)
            counts.append(self.protocolStats[p])
        self.frameProtocol = wx.Frame(self, -1, title = "Protocol summary",size=(400,500))
        panel = wx.Panel(self.frameProtocol,-1)
        sizerProtocol = wx.BoxSizer(wx.VERTICAL)
        fig = Figure()
        canvas = FigCanvas(panel, -1, fig)
        axes = fig.add_subplot(111)
        xx = range(len(protocol))
        print("协议统计窗口xx")
        print(xx)

        #y_width = np.arrange
        axes.bar(
            #left=x,
            x=xx,
            height=counts, 
            width=0.5, 
            align='center', 
            alpha=0.44,
            picker=5)
        axes.set_ylabel('Counts')
        axes.set_title('Protocol Summary')
        axes.set_xticks(xx)
        axes.set_xticklabels(protocol)
        #axes.show()
        canvas.draw()
        detailText = wx.StaticText(panel, -1, details,size=(400,200))
        
        sizerProtocol.Add(canvas,1,wx.LEFT | wx.TOP | wx.GROW)
        sizerProtocol.Add(detailText,0,wx.EXPAND)
        panel.SetSizer(sizerProtocol)
        self.frameProtocol.Show(True)

    def OnIP(self,e):
        ## display IP stats in HTML table format
        details = """<font face="Calibri" size="4"><b>IP Counts: %d</b><br>""" % self.ipCounts
        details += "<br><b>Source IP stats</b><br><br><table><tr><td>Source IP</td><td>Counts</td><td>%</td></tr>" 
        for p in self.sourceStats:
            details += "<tr><td>%s</td><td>%d</td><td>%.2f%%</td></tr>" % (
                p,self.sourceStats[p],float(self.sourceStats[p])*100/self.ipCounts)
        details += "</table><br><br><b>Destination IP stats</b><br><br><table><tr><td>Source IP</td><td>Counts</td><td>%</td></tr>"
        for p in self.destinationStats:
            details += "<tr><td>%s</td><td>%d</td><td>%.2f%%</td></tr>" % (
                p,self.destinationStats[p],float(self.destinationStats[p])*100/self.ipCounts)
        details += "</table></font>"
        self.frameIP = wx.Frame(self, -1, title = "IP summary",size=(500,500))
        panel = wx.Panel(self.frameIP,-1)
        #detailText = wx.StaticText(panel, -1, details,size=(400,200))
        detailHtml = wx.html.HtmlWindow(panel)
        detailHtml.SetPage(details)
        sizerIP = wx.BoxSizer(wx.VERTICAL)
        sizerIP.Add(detailHtml,1,wx.EXPAND)
        panel.SetSizer(sizerIP)
        self.frameIP.Show(True)
    def OnAbout(self,e):
        msg = """
         MySniffer is a GUI sniffer with following functions:

         * list all network interfaces
         * set filters before capturing 
         * capture network packets
         * analyze Protocol heads of packets(support IPv4, IPv6, TCP, UDP and ARP)
         * view bytes of packets(support Hex and Char)
         * protocol and IP stats
         * save captured packets in JSON format

         MySniffer is wrritten by Python using wxPython, winpcapy and matplotlib.

         By Wang Nanshu 
         October 2014
         Email: nanshu.wang@gmail.com
        """
        dlg = wx.MessageDialog(self, msg, "About", wx.OK)
        dlg.ShowModal()
        dlg.Destroy()
    def OnContent(self,e):
        msg = """
        Instruction:

         * Select Interfaces where you want to capture packets
         * Use Filters to select the type of packets you want to capture
         * Start capture packets by clicking on Start in Capture Menu or 
           the Start Icon in Toolbar
         * Stop capture packets by clicking on Stop in Capture Menu or 
           the Stop Icon in Toolbar
         * Select captured packet in the list, then the detail head 
           information and packet bytes will show bellow
         * Click Save to save the detail head information and packet bytes 
           in JSON format
         * Use Stats to see the protocol and IP statistics

        """
        dlg = wx.MessageDialog(self, msg, "Content", wx.OK)
        dlg.ShowModal()
        dlg.Destroy()



reload(sys)
#sys.setdefaultencoding('utf-8')

app = wx.App(False)
frame = PsMain(None, "MySniffer")
app.MainLoop()

