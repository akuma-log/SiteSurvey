from burp import IBurpExtender, IHttpListener, ITab, IMessageEditorController
import csv
from datetime import datetime
from java.awt import BorderLayout, FlowLayout, GridLayout, Dimension, Color, Font
from javax.swing import (JPanel, JScrollPane, JButton, JFileChooser, JLabel, 
                        JOptionPane, JDialog, JComboBox, JTextField, JList, 
                        JScrollPane, DefaultListModel, JPopupMenu, JMenuItem, JTabbedPane)
from java.io import File
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing import JTable
from java.awt.event import MouseAdapter
from javax.swing import DefaultCellEditor
from java.lang import Object
from javax.swing import JMenu  # Add this to your existing imports
from java.awt import Toolkit  # Add this with other imports
from javax.swing import ListSelectionModel  # Add with other imports
from javax.swing import JCheckBox  # Add this with your other imports
from javax.swing import JSplitPane
from burp import IMessageEditor


HIGHLIGHT_COLORS = {
    "Red": Color(255, 100, 100),
    "Grey": Color(200, 200, 200),
    "Yellow": Color(255, 255, 150),
    "Pink": Color(255, 150, 200)
}

class HighlightRenderer(DefaultTableCellRenderer):
    def __init__(self):
        DefaultTableCellRenderer.__init__(self)
        self.highlight_colors = {}  # Stores {request_number: color}
        self.dark_bg = Color(50, 50, 50)
        self.light_bg = Color.WHITE
        
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        
        # Get the actual model row
        model_row = table.convertRowIndexToModel(row)
        
        # Get the display value from column 0 (request number)
        display_value = table.getModel().getValueAt(model_row, 0)
        
        # Extract the actual request number (remove asterisk if present)
        try:
            if isinstance(display_value, str):
                # Remove asterisk and any non-numeric characters, then convert to int
                clean_value = display_value.replace('*', '').strip()
                if clean_value.isdigit():
                    req_no = int(clean_value)
                else:
                    req_no = None
            else:
                req_no = int(display_value)
        except:
            req_no = None
        
        # Detect theme
        bg_color = table.getBackground()
        is_dark = bg_color.getRed() < 128
        
        # Set default colors based on theme
        if is_dark:
            default_fg = Color.WHITE
            default_bg = self.dark_bg
            highlight_fg = Color.BLACK
        else:
            default_fg = Color.BLACK
            default_bg = self.light_bg
            highlight_fg = Color.WHITE
        
        # Apply default colors
        component.setForeground(default_fg)
        if not isSelected:
            component.setBackground(default_bg)
        
        # Highlight handling
        try:
            if req_no is not None:
                if req_no in self.highlight_colors:
                    color = self.highlight_colors[req_no]
                    component.setFont(Font("Dialog", Font.BOLD, 12))
                    component.setForeground(highlight_fg)
                    if is_dark:
                        r = max(0, color.getRed()-50)
                        g = max(0, color.getGreen()-50)
                        b = max(0, color.getBlue()-50)
                        component.setBackground(Color(r, g, b))
                    else:
                        r = min(255, color.getRed()+50)
                        g = min(255, color.getGreen()+50)
                        b = min(255, color.getBlue()+50)
                        component.setBackground(Color(r, g, b))
                    return component
        except Exception, e:
            pass
            
        component.setFont(Font("Dialog", Font.PLAIN, 12))
        return component
    
    def setHighlightColor(self, req_no, color):
        if color is None:
            if req_no in self.highlight_colors:
                del self.highlight_colors[req_no]
        else:
            self.highlight_colors[req_no] = color
    
    def migrateHighlights(self, old_to_new_map):
        new_highlights = {}
        for old_no, color in self.highlight_colors.items():
            if old_no in old_to_new_map:
                new_highlights[old_to_new_map[old_no]] = color
        self.highlight_colors = new_highlights
    


class TableMouseListener(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender
    
    def mousePressed(self, event):
        if event.isPopupTrigger():
            self._show_popup(event)
    
    def mouseReleased(self, event):
        if event.isPopupTrigger():
            self._show_popup(event)
    
    def _show_popup(self, event):
        # Get the row under the mouse
        row = self.extender.log_table.rowAtPoint(event.getPoint())
        
        # If right-clicked on a valid row, select it
        if row >= 0:
            # Select the clicked row if not already selected
            if not self.extender.log_table.isRowSelected(row):
                self.extender.log_table.clearSelection()
                self.extender.log_table.addRowSelectionInterval(row, row)
            
            # Show the popup menu
            self.extender.popup_menu.show(event.getComponent(), event.getX(), event.getY())

class MessageEditorController(IMessageEditorController):
    def __init__(self, extender):
        self._extender = extender
    
    def getRequest(self):
        selected_rows = self._extender.log_table.getSelectedRows()
        if len(selected_rows) == 1:
            model_row = self._extender.log_table.convertRowIndexToModel(selected_rows[0])
            if model_row < len(self._extender.requests):
                return self._extender.requests[model_row]['messageInfo'].getRequest()
        return None

    def getResponse(self):
        selected_rows = self._extender.log_table.getSelectedRows()
        if len(selected_rows) == 1:
            model_row = self._extender.log_table.convertRowIndexToModel(selected_rows[0])
            if model_row < len(self._extender.requests):
                response = self._extender.requests[model_row]['messageInfo'].getResponse()
                return response if response else None
        return None

    def getHttpService(self):
        selected_rows = self._extender.log_table.getSelectedRows()
        if len(selected_rows) == 1:
            model_row = self._extender.log_table.convertRowIndexToModel(selected_rows[0])
            if model_row < len(self._extender.requests):
                return self._extender.requests[model_row]['messageInfo'].getHttpService()
        return None



class BurpExtender(IBurpExtender, IHttpListener, ITab):  # Remove IMessageEditorController
    def __init__(self):
        self.requests = []
        self._custom_scope_rules = []
        self._scope_model = DefaultListModel()
        self._include_extensions = []
        self._exclude_extensions = []
        self._title_map = {}
        self._button_name_map = {}
        self._highlighted_rows = set()
        self._screen_groups = []
        self._current_screen = None
        self._next_branch_number = 1
        self._branch_counter = 1
        self._paused = False
        self._pending_requests = []

        self._filter_presets = {
        "Basic Filter": {
            'include': [],
            'exclude': ['.css', '.js', '.map', '.ico', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf']
        },
        "Comprehensive Filter": {
            'include': [],
            'exclude': ['.css', '.js', '.map', '.ico', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', 
                       '.eot', '.mp4', '.avi', '.mov', '.mp3', '.wav', '.pdf', '.doc', '.docx', '.zip', '.rar']
        },
        "Minimal Filter": {
            'include': [],
            'exclude': ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2']
        },
        "Security Focus Only": {
            'include': [],
            'exclude': ['.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.svg']
        }
        }

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Site Survey Logger")
        callbacks.registerHttpListener(self)
        
        # Initialize UI components
        self._init_ui_components()
        
        callbacks.addSuiteTab(self)
        print "[+] Site Survey Logger Loaded!"

    def getRequest(self):
        selected_rows = self.log_table.getSelectedRows()
        if len(selected_rows) == 1:
            model_row = self.log_table.convertRowIndexToModel(selected_rows[0])
            if model_row < len(self.requests):
                return self.requests[model_row]['messageInfo'].getRequest()
        return None

    def getResponse(self):
        selected_rows = self.log_table.getSelectedRows()
        if len(selected_rows) == 1:
            model_row = self.log_table.convertRowIndexToModel(selected_rows[0])
            if model_row < len(self.requests):
                response = self.requests[model_row]['messageInfo'].getResponse()
                return response if response else None
        return None

    def getHttpService(self):
        selected_rows = self.log_table.getSelectedRows()
        if len(selected_rows) == 1:
            model_row = self.log_table.convertRowIndexToModel(selected_rows[0])
            if model_row < len(self.requests):
                return self.requests[model_row]['messageInfo'].getHttpService()
        return None

    def _init_ui_components(self):
        self.log_panel = JPanel(BorderLayout())
        
        column_names = [
            "No.", "Screen Name", "Screen URL", "Button Name", 
            "Method", "Transition URL", "Params", "Status", "Length"
        ]
        self.log_model = DefaultTableModel()
        self.log_model.setColumnIdentifiers(column_names)
        self.log_table = JTable(self.log_model)
        
        # Initialize renderer
        self.highlight_renderer = HighlightRenderer()
        self.log_table.setDefaultRenderer(Object, self.highlight_renderer)
        
        # Set Burp Suite style selection colors
        self.log_table.setShowGrid(True)
        self.log_table.setGridColor(Color.LIGHT_GRAY)
        self.log_table.setSelectionBackground(Color(64, 114, 196))
        self.log_table.setSelectionForeground(Color.WHITE)
        self.log_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        
        # Initialize control buttons
        self._setup_control_buttons()
        
        # Create the message editor controller
        self._message_controller = MessageEditorController(self)
        
        # Simple message viewers (remove any tabbed pane code)
        self._request_viewer = self._callbacks.createMessageEditor(None, False)
        self._response_viewer = self._callbacks.createMessageEditor(None, False)
        
        # Replace the message_split_pane with tabbed pane
        self.message_tabbed_pane = JTabbedPane()
        self.message_tabbed_pane.addTab("Request", self._request_viewer.getComponent())
        self.message_tabbed_pane.addTab("Response", self._response_viewer.getComponent())
        
        # Add selection listener
        self.log_table.getSelectionModel().addListSelectionListener(
            self._handle_row_selection)
        
        self._setup_editable_columns()
        self._setup_context_menu()
        
    def _setup_editable_columns(self):
        self.log_table.getColumnModel().getColumn(0).setCellEditor(  # Screen Name
            DefaultCellEditor(JTextField()))
        self.log_table.getColumnModel().getColumn(2).setCellEditor(  # Button Name
            DefaultCellEditor(JTextField()))
        self.log_table.getColumnModel().getColumn(3).setCellEditor(  # Method
            DefaultCellEditor(JTextField()))
        
    def _handle_row_selection(self, event):
        """Show request/response details when a row is selected"""
        if event.getValueIsAdjusting():
            return
            
        selected_rows = self.log_table.getSelectedRows()
        if len(selected_rows) == 1:
            model_row = self.log_table.convertRowIndexToModel(selected_rows[0])
            if model_row < len(self.requests):
                request_data = self.requests[model_row]
                
                # Set request (isRequest=True)
                self._request_viewer.setMessage(
                    request_data['messageInfo'].getRequest(), 
                    True
                )
                
                # Set response (isRequest=False) - FIXED
                response = request_data['messageInfo'].getResponse()
                self._response_viewer.setMessage(response, False)

    def _setup_context_menu(self):
        self.popup_menu = JPopupMenu()
        
        # Send to Repeater
        send_to_repeater_item = JMenuItem("Send to Repeater")
        send_to_repeater_item.addActionListener(lambda e: self._view_in_repeater())
        self.popup_menu.add(send_to_repeater_item)
        
        # Add separator
        self.popup_menu.addSeparator()
        
        # Delete Selected
        delete_item = JMenuItem("Delete Selected")
        delete_item.addActionListener(lambda e: self._delete_selected())
        self.popup_menu.add(delete_item)
        
        # Add separator
        self.popup_menu.addSeparator()
        
        # Highlight Submenu
        highlight_menu = JMenu("Highlight")
        for color_name, color in HIGHLIGHT_COLORS.items():
            color_item = JMenuItem(color_name)
            color_item.addActionListener(lambda e, c=color: self._highlight_selected(c))
            highlight_menu.add(color_item)
        
        # Remove Highlight
        remove_highlight = JMenuItem("Remove Highlight")
        remove_highlight.addActionListener(lambda e: self._highlight_selected(None))
        highlight_menu.add(remove_highlight)
        
        self.popup_menu.add(highlight_menu)
        
        # Add separator
        self.popup_menu.addSeparator()
        
        # Copy
        copy_item = JMenuItem("Copy")
        copy_item.addActionListener(lambda e: self._copy_selected())
        self.popup_menu.add(copy_item)
        
        # Attach the popup menu to the table
        self.log_table.setComponentPopupMenu(self.popup_menu)

    def _create_color_handler(self, color):
        """Helper to create color handlers that maintain the color reference"""
        return lambda e: self._highlight_selected(color)

    def _highlight_selected(self, color):
        selected_rows = [self.log_table.convertRowIndexToModel(i) 
                    for i in self.log_table.getSelectedRows()]
        if not selected_rows:
            return

        for row in selected_rows:
            # Get the display value from the table to find the actual request number
            display_value = self.log_model.getValueAt(row, 0)
            
            # Extract the actual request number (remove asterisk if present)
            try:
                if isinstance(display_value, str):
                    # Remove asterisk and any non-numeric characters, then convert to int
                    clean_value = display_value.replace('*', '').strip()
                    if clean_value.isdigit():
                        req_no = int(clean_value)
                    else:
                        req_no = None
                else:
                    req_no = int(display_value)
            except:
                req_no = None
            
            if req_no is not None:
                self.highlight_renderer.setHighlightColor(req_no, color)
        
        self.log_table.repaint()

    def _setup_control_buttons(self):
        # Initialize all buttons
        self.scope_button = JButton("Manage Scope", actionPerformed=self._show_scope_dialog)
        self.filter_button = JButton("Filter Extensions", actionPerformed=self._show_filter_dialog)
        self.export_button = JButton("Export to Excel", actionPerformed=self._export_to_excel)
        self.clear_button = JButton("Clear All", actionPerformed=self._confirm_clear)
        self.pause_button = JButton("Pause Logging", actionPerformed=self._toggle_pause)
        self.status_label = JLabel("Ready. 0 requests captured")

    def _export_to_excel(self, event):
        if not self.requests:
            JOptionPane.showMessageDialog(None,
                "No data to export",
                "Export Failed",
                JOptionPane.WARNING_MESSAGE)
            return

        # Create file chooser
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("Save Excel File")
        file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        file_chooser.setSelectedFile(File("site_survey_export.csv"))
        
        result = file_chooser.showSaveDialog(None)
        
        if result == JFileChooser.APPROVE_OPTION:
            selected_file = file_chooser.getSelectedFile()
            file_path = selected_file.getAbsolutePath()
            
            # Ensure .csv extension
            if not file_path.lower().endswith('.csv'):
                file_path += '.csv'
            
            try:
                with open(file_path, 'wb') as csvfile:
                    writer = csv.writer(csvfile)
                    
                    # Write headers
                    headers = [
                        "No.", "Screen Name", "Screen URL", "Button Name", 
                        "Method", "Transition URL", "Params", "Status", "Length"
                    ]
                    writer.writerow(headers)
                    
                    # Write data
                    for req in self.requests:
                        writer.writerow([
                            req['number'],
                            req.get('screen_name', ''),
                            req['screen_url'],
                            req.get('button_name', ''),
                            req['method'],
                            req.get('transition_url', ''),
                            req.get('params', 0),
                            req.get('status', ''),
                            req.get('length', 0)
                        ])
                
                JOptionPane.showMessageDialog(None,
                    "Exported {} requests to:\n{}".format(len(self.requests), file_path),
                    "Export Successful",
                    JOptionPane.INFORMATION_MESSAGE)
                    
            except Exception as e:
                JOptionPane.showMessageDialog(None,
                    "Export failed: {}".format(str(e)),
                    "Error",
                    JOptionPane.ERROR_MESSAGE)



    def _delete_selected(self, event=None):
        selected_rows = sorted([self.log_table.convertRowIndexToModel(i) 
                            for i in self.log_table.getSelectedRows()], reverse=True)
        if not selected_rows:
            return

        confirm = JOptionPane.showConfirmDialog(
            None,
            "Delete {} selected requests?".format(len(selected_rows)),
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION)
        
        if confirm == JOptionPane.YES_OPTION:
            # Delete by row index (since table rows align with requests list)
            # Build new requests list excluding selected rows
            new_requests = []
            old_to_new_map = {}
            new_number = 1
            
            for i, req in enumerate(self.requests):
                if i not in selected_rows:  # Use index, not display number
                    old_number = req['number']
                    req['number'] = new_number
                    old_to_new_map[old_number] = new_number
                    new_requests.append(req)
                    new_number += 1
            
            self.requests = new_requests
            
            # Migrate highlights
            self.highlight_renderer.migrateHighlights(old_to_new_map)
            
            # Update display
            self._update_display()
            self._update_status()

    def _toggle_highlight(self, event=None):
        selected_rows = [self.log_table.convertRowIndexToModel(i) 
                    for i in self.log_table.getSelectedRows()]
        if not selected_rows:
            return

        for row in selected_rows:
            screen_name = self.log_model.getValueAt(row, 0)
            if screen_name and str(screen_name).strip() and screen_name.startswith("Screen"):
                try:
                    screen_num = int(screen_name.split()[-1])
                    if screen_num in self._highlighted_rows:
                        self._highlighted_rows.remove(screen_num)
                    else:
                        self._highlighted_rows.add(screen_num)
                except:
                    pass
        
        # Update the renderer with new highlighted rows
        self.highlight_renderer.setHighlightedRows(self._highlighted_rows)
        self.log_table.repaint()

    def _make_screen(self, event=None):
        selected_rows = [self.log_table.convertRowIndexToModel(i) 
                    for i in self.log_table.getSelectedRows()]
        if not selected_rows:
            return

        max_screen = max([req.get('screen_number', 0) for req in self.requests])
        screen_num = max_screen + 1

        for row in selected_rows:
            screen_url = self.log_model.getValueAt(row, 1)  # Screen URL column
            for req in self.requests:
                if req['screen_url'] == screen_url:
                    req['screen_number'] = screen_num
                    req['screen_name'] = "Screen {}".format(screen_num)

        self._update_display()

    def _view_in_repeater(self):
        selected_rows = [self.log_table.convertRowIndexToModel(i) 
                        for i in self.log_table.getSelectedRows()]
        if not selected_rows:
            return
        
        # Get the first selected request
        row = selected_rows[0]
        
        # DIRECTLY use the row index to get the request from self.requests
        if row < len(self.requests):
            req_data = self.requests[row]
            
            try:
                message_info = req_data['messageInfo']
                
                # Send to Repeater using the actual messageInfo
                self._callbacks.sendToRepeater(
                    message_info.getHttpService().getHost(),
                    message_info.getHttpService().getPort(),
                    message_info.getHttpService().getProtocol() == "https",
                    message_info.getRequest(),
                    "SiteSurvey Request #{}".format(req_data['number'])
                )
                
                # Switch to Repeater tab
                try:
                    self._callbacks.activateBurpTab("Repeater")
                except:
                    pass
                    
                JOptionPane.showMessageDialog(None,
                    "Request #{} sent to Repeater tab".format(req_data['number']),
                    "Send to Repeater",
                    JOptionPane.INFORMATION_MESSAGE)
                    
            except Exception as e:
                JOptionPane.showMessageDialog(None,
                    "Error sending to Repeater: {}".format(str(e)),
                    "Error",
                    JOptionPane.ERROR_MESSAGE)

    def _copy_selected(self, event=None):
        selected_rows = [self.log_table.convertRowIndexToModel(i) 
                    for i in self.log_table.getSelectedRows()]
        if not selected_rows:
            return

        try:
            clipboard_data = []
            for row in selected_rows:
                row_data = []
                for col in range(self.log_model.getColumnCount()):
                    value = self.log_model.getValueAt(row, col)
                    row_data.append(str(value) if value is not None else "")
                clipboard_data.append("\t".join(row_data))

            from java.awt import Toolkit
            from java.awt.datatransfer import StringSelection
            toolkit = Toolkit.getDefaultToolkit()
            clipboard = toolkit.getSystemClipboard()
            clipboard.setContents(StringSelection("\n".join(clipboard_data)), None)

            JOptionPane.showMessageDialog(
                None,
                "Copied {} rows to clipboard.".format(len(selected_rows)),
                "Copy Successful",
                JOptionPane.INFORMATION_MESSAGE
            )
        except Exception as e:
            JOptionPane.showMessageDialog(
                None,
                "Copy failed: {}".format(str(e)),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )

    def _organize_branches(self):
        # Group by screen number
        screens = {}
        for req in self.requests:
            if 'screen_number' in req:
                screen_num = req['screen_number']
                if screen_num not in screens:
                    screens[screen_num] = []
                screens[screen_num].append(req)
        
        # Number branches within each screen
        for screen_num, screen_reqs in screens.items():
            # Sort by original request number to maintain order
            screen_reqs.sort(key=lambda x: x['number'])
            for i, req in enumerate(screen_reqs, 1):
                req['branch_number'] = i

    def _update_display(self):
        # Store current highlights before clearing
        current_highlights = self.highlight_renderer.highlight_colors.copy()
        
        self.log_model.setRowCount(0)
        
        # Track seen URLs AND methods to detect duplicates
        seen_requests = {}  # key: (url, method) -> first occurrence number
        display_counter = 1  # Counter for sequential display numbers
        
        for req in self.requests:
            # First check scope
            try:
                url = req['messageInfo'].getUrl()
                if not self._check_custom_scope(url):
                    continue  # Skip if not in scope
            except:
                # If URL can't be parsed, skip this request
                continue
                
            # Then check file extension filters
            if not self._should_display(req):
                continue  # Skip if filtered by extension
                
            # If we get here, the request passed both filters
            # Check for duplicate requests (same actual URL AND same method)
            actual_url = req['messageInfo'].getUrl().toString()
            method = req['method']
            request_key = (actual_url, method)
            
            display_number = display_counter
            display_counter += 1
            
            if request_key in seen_requests:
                first_occurrence = seen_requests[request_key]
                display_number = "{}*".format(first_occurrence)
            else:
                seen_requests[request_key] = display_number
            
            # Rest of the display code...
            status = str(req.get('status', "Pending"))
            if status.isdigit():
                status_code = int(status)
                if 200 <= status_code < 300:
                    status = "%s (OK)" % status_code
                elif status_code >= 400:
                    status = "%s (Error)" % status_code
            
            self.log_model.addRow([
                display_number,
                req.get('screen_name', ""),
                req.get('screen_url', ""),
                req.get('button_name', ""),
                method,
                req.get('transition_url', ""),
                req.get('params', 0),
                status,
                req.get('length', 0)
            ])
        
        # Restore highlights
        self.highlight_renderer.highlight_colors = current_highlights
        self.log_table.repaint()

    def _renumber_requests(self):
        """Renumber requests after deletions"""
        # First renumber all requests sequentially
        for i, req in enumerate(self.requests, 1):
            req['number'] = i
        
        # Then update branch numbers
        self._screen_map = {}
        for row in range(self.log_model.getRowCount()):
            branch_info = str(self.log_model.getValueAt(row, 1))
            if " of " in branch_info:
                screen_num, branch_num = map(int, branch_info.split(" of "))
                self._screen_map[screen_num] = self._screen_map.get(screen_num, 0) + 1
                self.log_model.setValueAt("{} of {}".format(screen_num, self._screen_map[screen_num]), row, 1)


    def _renumber_requests(self):
        """Renumber requests after deletions"""
        # First renumber all requests sequentially
        for i, req in enumerate(self.requests, 1):
            req['number'] = i
        
        # Then update branch numbers
        self._screen_map = {}
        for row in range(self.log_model.getRowCount()):
            branch_info = str(self.log_model.getValueAt(row, 1))
            if " of " in branch_info:
                screen_num, branch_num = map(int, branch_info.split(" of "))
                self._screen_map[screen_num] = self._screen_map.get(screen_num, 0) + 1
                self.log_model.setValueAt("{} of {}".format(screen_num, self._screen_map[screen_num]), row, 1)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # First check if the URL is in scope
        url = messageInfo.getUrl()
        if not self._check_custom_scope(url):
            return
        
        if self._paused:
            if messageIsRequest:
                return

        if messageIsRequest:
            # Process request...
            analyzed = self._helpers.analyzeRequest(messageInfo)
            url_str = url.toString()
            
            entry = {
                'number': len(self.requests) + 1,
                'screen_url': "",
                'button_name': "",
                'method': analyzed.getMethod(),
                'transition_url': url_str,
                'params': self._get_parameters_count(analyzed),
                'status': "Pending",
                'length': 0,
                'messageInfo': messageInfo,  # Store the messageInfo object
                'request_hash': hash(messageInfo.getRequest().tostring())
            }
            self.requests.append(entry)
        else:
            # Process response...
            response = messageInfo.getResponse()
            if response:
                response_info = self._helpers.analyzeResponse(response)
                status_code = str(response_info.getStatusCode())
                response_length = len(response)
                
                # Find matching request and UPDATE its messageInfo
                request_hash = hash(messageInfo.getRequest().tostring())
                for req in self.requests:
                    if req.get('request_hash') == request_hash and req['status'] == "Pending":
                        req['status'] = status_code
                        req['length'] = response_length
                        # CRITICAL: Update the stored messageInfo with the response
                        req['messageInfo'] = messageInfo  # This line is missing!
                        break
        
        self._update_status()
        self._update_display()


    def _get_parameters_count(self, analyzed_request):
        """Count parameters in request body (form data)"""
        body_params = 0
        
        for param in analyzed_request.getParameters():
            param_type = param.getType()
            param_name = param.getName()
            
            # For application/x-www-form-urlencoded POST data, parameters have type 1 (PARAM_URL)
            # but they are actually in the request body, not the URL
            if param_type == 1:  # This includes both URL params and form body params
                # We need to check if this is actually a body parameter
                # One way is to check if the request method is POST
                method = analyzed_request.getMethod()
                if method.upper() == "POST":
                    # For POST requests, assume type 1 parameters are in the body
                    body_params += 1
                else:
                    # For GET requests, type 1 parameters are URL parameters
                    pass
            elif param_type == 0:  # PARAM_BODY (less common)
                body_params += 1
        
        return body_params




    def getTabCaption(self):
        return "Site Survey Pro"

    def getUiComponent(self):
        main_panel = JPanel(BorderLayout())
        
        # Top Control Panel
        control_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        control_panel.add(self.scope_button)
        control_panel.add(self.filter_button)
        control_panel.add(self.export_button) 
        control_panel.add(self.clear_button)
        control_panel.add(self.pause_button)
        control_panel.add(self.status_label)
        
        # TOP SECTION: Log table (full width)
        log_panel = JPanel(BorderLayout())
        log_panel.add(JLabel("Request Log:"), BorderLayout.NORTH)
        log_panel.add(JScrollPane(self.log_table), BorderLayout.CENTER)
        
        # BOTTOM SECTION: Request and Response side by side
        # Request Panel (Left)
        request_panel = JPanel(BorderLayout())
        request_panel.add(JLabel("Request"), BorderLayout.NORTH)
        request_panel.add(self._request_viewer.getComponent(), BorderLayout.CENTER)
        
        # Response Panel (Right)
        response_panel = JPanel(BorderLayout())
        response_panel.add(JLabel("Response"), BorderLayout.NORTH)
        response_panel.add(self._response_viewer.getComponent(), BorderLayout.CENTER)
        
        # Split pane for Request/Response
        req_res_split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        req_res_split_pane.setLeftComponent(request_panel)
        req_res_split_pane.setRightComponent(response_panel)
        req_res_split_pane.setResizeWeight(0.5)  # 50/50 split
        
        # MAIN Split pane: Logs on top, Request/Response on bottom
        main_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        main_split_pane.setTopComponent(log_panel)
        main_split_pane.setBottomComponent(req_res_split_pane)
        main_split_pane.setResizeWeight(0.7)  # 70% for logs, 30% for req/res
        
        # Footer
        footer_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        footer_panel.add(JLabel("Created by Hossain Tanvir", foreground=Color.GRAY))
        
        # Final Assembly
        main_panel.add(control_panel, BorderLayout.NORTH)
        main_panel.add(main_split_pane, BorderLayout.CENTER)
        main_panel.add(footer_panel, BorderLayout.SOUTH)
        
        return main_panel

    def _toggle_pause(self, event):
        self._paused = not self._paused
        
        if self._paused:
            self.pause_button.setText("Resume Logging")
            self.status_label.setText("PAUSED - Logging stopped")
            print "[+] Logging paused"
        else:
            self.pause_button.setText("Pause Logging")
            # Simply clear any pending requests without asking
            self._pending_requests = []
            self._update_status()
            print "[+] Logging resumed"

    def _process_single_message(self, toolFlag, messageInfo):
        """Helper to process a single message"""
        # First check if the URL is in scope
        url = messageInfo.getUrl()
        if not self._check_custom_scope(url):
            return
        
        # Process request (messageIsRequest is always True for pending requests)
        analyzed = self._helpers.analyzeRequest(messageInfo)
        url_str = url.toString()
        
        entry = {
            'number': len(self.requests) + 1,
            'screen_url': url_str,
            'button_name': self._extract_button_name(messageInfo.getRequest().tostring()),
            'method': analyzed.getMethod(),
            'transition_url': url_str,
            'params': self._get_parameters_count(analyzed),
            'status': "Pending",
            'length': 0,
            'messageInfo': messageInfo,
            'request_hash': hash(messageInfo.getRequest().tostring())
        }
        self.requests.append(entry)
        
        # Now we need to manually send the request and capture the response
        try:
            # Send the request using Burp's makeHttpRequest
            response = self._callbacks.makeHttpRequest(
                messageInfo.getHttpService(),
                messageInfo.getRequest()
            )
            
            # Process the response
            if response:
                response_info = self._helpers.analyzeResponse(response)
                status_code = str(response_info.getStatusCode())
                response_length = len(response)
                
                # Update the request entry with response data
                entry['status'] = status_code
                entry['length'] = response_length
                
        except Exception as e:
            print "Error processing pending request: {}".format(str(e))
            entry['status'] = "Error"
        
        # FORCE update the display after each request
        self._update_status()
        self._update_display()


    def _extract_button_name(self, request_str):
        """Simple method to extract button names from HTML"""
        # Try to find button value
        if "value=" in request_str:
            try:
                start = request_str.index("value=") + 7
                end = request_str.index('"', start)
                return request_str[start:end]
            except:
                pass
                
        # Try to find button text
        if ">" in request_str and "<" in request_str:
            try:
                start = request_str.index(">") + 1
                end = request_str.index("<", start)
                return request_str[start:end].strip()
            except:
                pass
                
        return "Button"

    def _confirm_clear(self, event):
        """Show confirmation dialog before clearing all requests"""
        confirm = JOptionPane.showConfirmDialog(
            None,
            "Are you sure you want to clear all requests?",
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION)
            
        if confirm == JOptionPane.YES_OPTION:
            self.requests = []
            self.log_model.setRowCount(0)
            self._title_map = {}
            self._button_name_map = {}
            
            # CLEAR HIGHLIGHT COLORS - ADD THIS LINE
            self.highlight_renderer.highlight_colors.clear()
            
            self._update_status()
            print "[+] All requests and highlights cleared"

    def _check_custom_scope(self, url):
        # If no scope rules defined, include everything
        if not self._custom_scope_rules:
            return True
        
        url_str = url.toString()
        protocol = url.getProtocol()
        host = url.getHost()
        port = url.getPort()
        path = url.getPath() or "/"  # Ensure path is at least "/"
        
        # Handle default ports
        if port == -1:
            port = 443 if protocol == "https" else 80
        
        # Check each rule
        for rule in self._custom_scope_rules:
            rule_protocol, rule_host, rule_port, rule_path = rule
            
            # Protocol check
            if rule_protocol and rule_protocol != protocol:
                continue
                
            # Host check (supports wildcards like *.example.com)
            if rule_host:
                if rule_host.startswith("*."):
                    if not host.endswith(rule_host[1:]):
                        continue
                elif rule_host.lower() != host.lower():
                    continue
                    
            # Port check
            if rule_port and rule_port != port:
                continue
                
            # Path check - if rule_path is specified, check if path starts with it
            if rule_path:
                # Ensure both paths start with /
                rule_path = rule_path if rule_path.startswith("/") else "/" + rule_path
                current_path = path if path.startswith("/") else "/" + path
                
                # Check if the current path starts with the rule path
                if not current_path.startswith(rule_path):
                    continue
            # If no path specified in rule, include ALL paths for this host
            # (This is the key fix - if no path rule, don't skip the request)
                    
            # If we get here, all specified rule components matched
            return True
        
        # No rules matched
        return False
    
    def _show_scope_dialog(self, event):
        dialog = JDialog()
        dialog.setTitle("Manage Scope Rules")
        dialog.setSize(500, 400)
        dialog.setLayout(BorderLayout())
        dialog.setModal(True)

        # Current Rules List
        rules_list = JList(self._scope_model)
        scroll_pane = JScrollPane(rules_list)

        # Input Panel
        input_panel = JPanel(GridLayout(4, 2, 5, 5))
        
        # Protocol
        input_panel.add(JLabel("Protocol:"))
        protocol_combo = JComboBox(["http", "https", "Any"])
        input_panel.add(protocol_combo)
        
        # Host (supports wildcards like *.example.com)
        input_panel.add(JLabel("Host (e.g. example.com or *.example.com):"))
        host_field = JTextField()
        input_panel.add(host_field)
        
        # Port
        input_panel.add(JLabel("Port (optional):"))
        port_field = JTextField()
        input_panel.add(port_field)
        
        # Path
        input_panel.add(JLabel("Path (e.g. /api):"))
        path_field = JTextField()
        input_panel.add(path_field)

        # Button Panel
        button_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        
        def add_rule(e):
            protocol = str(protocol_combo.getSelectedItem())
            host = host_field.getText().strip()
            port = port_field.getText().strip()
            path = path_field.getText().strip()
            
            if not any([host, port, path]):
                JOptionPane.showMessageDialog(dialog, 
                    "At least one field (Host, Port, or Path) must be specified", 
                    "Error", 
                    JOptionPane.ERROR_MESSAGE)
                return
                
            # Add the new rule
            rule = (
                protocol if protocol != "Any" else None,
                host.lower() if host else None,
                int(port) if port else None,
                path if path else None
            )
            self._custom_scope_rules.append(rule)
            
            # Display in readable format
            display_text = "%s://%s:%s%s" % (
                rule[0] or "*",
                rule[1] or "*",
                rule[2] or "*",
                rule[3] or "/*"
            )
            self._scope_model.addElement(display_text)
            
            # Clear fields
            host_field.setText("")
            port_field.setText("")
            path_field.setText("")
            
            # Apply scope to existing requests
            self._apply_scope_filter()  # <-- Add this line

        add_btn = JButton("Add Rule", actionPerformed=add_rule)
        button_panel.add(add_btn)
        
        remove_btn = JButton("Remove Selected", 
            actionPerformed=lambda e: self._remove_scope_rule(rules_list))
        button_panel.add(remove_btn)

        # Main Layout
        main_panel = JPanel(BorderLayout())
        main_panel.add(scroll_pane, BorderLayout.CENTER)
        
        bottom_panel = JPanel(BorderLayout())
        bottom_panel.add(input_panel, BorderLayout.NORTH)
        bottom_panel.add(button_panel, BorderLayout.SOUTH)
        
        dialog.add(main_panel, BorderLayout.CENTER)
        dialog.add(bottom_panel, BorderLayout.SOUTH)
        dialog.setLocationRelativeTo(None)
        dialog.setVisible(True)

    def _apply_scope_filter(self):
        """Filter existing requests based on current scope rules"""
        # Don't modify self.requests - just update the display
        # The filtering happens in _update_display()
        self._update_display()

    def _show_filter_dialog(self, event):
        dialog = JDialog()
        dialog.setTitle("Filter by File Extension")
        dialog.setSize(500, 400)  # Increased size for new controls
        dialog.setLayout(BorderLayout())
        dialog.setModal(True)
        
        # Main content panel
        main_panel = JPanel(BorderLayout(10, 10))
        
        # PRESET SELECTION PANEL (NEW)
        preset_panel = JPanel(BorderLayout(5, 5))
        preset_panel.add(JLabel("Quick Presets:"), BorderLayout.NORTH)
        self.preset_combo = JComboBox(["Custom", "Basic Filter", "Comprehensive Filter", "Minimal Filter", "Security Focus Only"])
        self.preset_combo.addActionListener(lambda e: self._apply_preset_filter())
        preset_panel.add(self.preset_combo, BorderLayout.CENTER)
        
        # Extension Input Panel
        input_panel = JPanel(GridLayout(4, 1, 5, 5))
        
        # Include Extensions
        include_panel = JPanel(BorderLayout())
        include_panel.add(JLabel("Show ONLY these extensions (comma separated):"), BorderLayout.NORTH)
        self.include_field = JTextField(",".join(self._include_extensions))
        include_panel.add(self.include_field, BorderLayout.CENTER)
        
        # Exclude Extensions
        exclude_panel = JPanel(BorderLayout())
        exclude_panel.add(JLabel("HIDE these extensions (comma separated):"), BorderLayout.NORTH)
        self.exclude_field = JTextField(",".join(self._exclude_extensions))
        exclude_panel.add(self.exclude_field, BorderLayout.CENTER)
        
        input_panel.add(include_panel)
        input_panel.add(exclude_panel)
        
        # Info label
        info_label = JLabel("Note: Include filter has priority over exclude filter")
        info_label.setForeground(Color.GRAY)
        
        # Button Panel
        button_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        apply_btn = JButton("Apply Filters", actionPerformed=lambda e: self._apply_filters(dialog))
        button_panel.add(apply_btn)
        
        cancel_btn = JButton("Cancel", actionPerformed=lambda e: dialog.dispose())
        button_panel.add(cancel_btn)
        
        # Clear btn
        clear_btn = JButton("Clear All Filters", actionPerformed=lambda e: self._clear_filters())
        button_panel.add(clear_btn)
        
        # Assembly
        main_panel.add(preset_panel, BorderLayout.NORTH)
        main_panel.add(input_panel, BorderLayout.CENTER)
        main_panel.add(info_label, BorderLayout.SOUTH)
        
        dialog.add(main_panel, BorderLayout.CENTER)
        dialog.add(button_panel, BorderLayout.SOUTH)
        dialog.setLocationRelativeTo(None)
        dialog.setVisible(True)

    def _apply_preset_filter(self):
        """Apply selected preset filter"""
        preset_name = str(self.preset_combo.getSelectedItem())
        
        if preset_name == "Custom":
            # Don't change anything for custom selection
            return
        
        if preset_name in self._filter_presets:
            preset = self._filter_presets[preset_name]
            
            # Update the text fields with preset values
            include_text = ",".join(preset['include'])
            exclude_text = ",".join(preset['exclude'])
            
            self.include_field.setText(include_text)
            self.exclude_field.setText(exclude_text)
            
            # Show confirmation
            print "[+] Applied preset: {}".format(preset_name)

    def _clear_filters(self):
        """Clear all extension filters"""
        self._include_extensions = []
        self._exclude_extensions = []
        self._update_display()
        print "[+] All extension filters cleared"

    def _apply_filters(self, dialog):
        include_text = self.include_field.getText().strip()
        exclude_text = self.exclude_field.getText().strip()

        # Process include extensions
        self._include_extensions = []
        if include_text:
            extensions = [ext.strip() for ext in include_text.split(",") if ext.strip()]
            for ext in extensions:
                if not ext.startswith('.'):
                    ext = '.' + ext
                self._include_extensions.append(ext.lower())

        # Process exclude extensions
        self._exclude_extensions = []
        if exclude_text:
            extensions = [ext.strip() for ext in exclude_text.split(",") if ext.strip()]
            for ext in extensions:
                if not ext.startswith('.'):
                    ext = '.' + ext
                self._exclude_extensions.append(ext.lower())

        dialog.dispose()
        self._update_display()  # Refresh display with new filters
        
        # Show filter summary
        total_filters = len(self._include_extensions) + len(self._exclude_extensions)
        print "[+] Applied {} filter rules ({} include, {} exclude)".format(
            total_filters, len(self._include_extensions), len(self._exclude_extensions))

    def _should_display(self, entry):
        # Use the actual URL from the messageInfo, not the blank screen_url
        try:
            url = entry['messageInfo'].getUrl().toString()
        except:
            url = entry.get('screen_url', '')
        
        # Check include extensions
        if self._include_extensions:
            has_include = any(url.lower().endswith(ext.lower()) for ext in self._include_extensions)
            if not has_include:
                return False
        
        # Check exclude extensions
        if self._exclude_extensions:
            has_exclude = any(url.lower().endswith(ext.lower()) for ext in self._exclude_extensions)
            if has_exclude:
                return False
        
        return True


    def _remove_scope_rule(self, rules_list):
        selected = rules_list.getSelectedIndex()
        if selected >= 0:
            self._scope_model.remove(selected)
            self._custom_scope_rules.pop(selected)
            self._apply_scope_filter()  # <-- Add this line

    def _update_status(self):
        pending_count = len(self._pending_requests)
        status_text = "Captured: {} requests".format(len(self.requests))
        
        if pending_count > 0:
            status_text += " | {} pending".format(pending_count)
        
        status_text += " | Last: {}".format(datetime.now().strftime("%H:%M:%S"))
        
        self.status_label.setText(status_text)

    def _get_parameters(self, analyzed):
        return dict(
            (param.getName(), param.getValue())
            for param in analyzed.getParameters()
        )

    def _get_cookies(self, analyzed):
        return dict(
            (h.split("=",1)[0].strip(), h.split("=",1)[1].strip())
            for h in analyzed.getHeaders()
            if h.lower().startswith("cookie:")
        )

    def getTabCaption(self):
        return "Site Survey Pro"

