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
from javax.swing import JButton, AbstractCellEditor
from java.awt.event import ActionListener, MouseAdapter
from java.awt import Cursor
from burp import IBurpExtender, IHttpListener, ITab, IMessageEditorController
from javax.swing import Timer


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
    

class CopyButtonMouseListener(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender
        self.timer = None
        
    def mouseMoved(self, event):
        table = event.getSource()
        point = event.getPoint()
        row = table.rowAtPoint(point)
        column = table.columnAtPoint(point)
        
        # Show hand cursor only on Transition URL column
        if column == 5 and row >= 0:
            table.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        else:
            table.setCursor(Cursor.getDefaultCursor())
            
    def mouseClicked(self, event):
        table = event.getSource()
        point = event.getPoint()
        row = table.rowAtPoint(point)
        column = table.columnAtPoint(point)
        
        # Handle click on Transition URL column
        if column == 5 and row >= 0:
            model_row = table.convertRowIndexToModel(row)
            if (hasattr(self.extender, '_display_to_request_map') and 
                model_row < len(self.extender._display_to_request_map)):
                
                actual_index = self.extender._display_to_request_map[model_row]
                if actual_index < len(self.extender.requests):
                    req_data = self.extender.requests[actual_index]
                    url = req_data.get('transition_url', '')
                    if url:
                        from java.awt import Toolkit
                        from java.awt.datatransfer import StringSelection
                        toolkit = Toolkit.getDefaultToolkit()
                        clipboard = toolkit.getSystemClipboard()
                        clipboard.setContents(StringSelection(url), None)
                        
                        # Show brief popup message
                        self._show_brief_popup(table, point, "Copied!")
    
    def _show_brief_popup(self, component, point, message):
        # Create a small popup label
        popup = JPopupMenu()
        popup.setBorder(None)
        
        label = JLabel(message)
        label.setForeground(Color.WHITE)
        label.setBackground(Color(70, 130, 180))  # Steel blue color
        label.setOpaque(True)
        label.setBorder(JPopupMenu().getBorder())
        popup.add(label)
        
        # Show popup near the click position
        popup.show(component, point.x + 10, point.y - 25)
        
        # Auto-close after 1 second
        if self.timer and self.timer.isRunning():
            self.timer.stop()
            
        class PopupCloser(ActionListener):
            def __init__(self, popup):
                self.popup = popup
            def actionPerformed(self, e):
                self.popup.setVisible(False)
                
        self.timer = Timer(1000, PopupCloser(popup))  # 1000ms = 1 second
        self.timer.setRepeats(False)
        self.timer.start()


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
        self._exclude_directories = []  # List of directory paths to exclude
        self._include_directories = []  # List of directory paths to include only
        self._hide_duplicates = False

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
        
        # Force UTF-8 encoding for better international character support
        import sys
        reload(sys)
        sys.setdefaultencoding('utf-8')
        
        # Initialize UI components
        self._init_ui_components()
        
        callbacks.addSuiteTab(self)


    def _make_selection_more_visible(self):
        """Make selection more visible like traditional Burp"""
        # Set selection colors to be more prominent
        self.log_table.setSelectionBackground(Color(64, 114, 196))  # Bright blue
        self.log_table.setSelectionForeground(Color.WHITE)
        
        # Make selection persist through updates
        self.log_table.putClientProperty("JTable.autoStartsEdit", False)

    def _setup_persistent_selection(self):
        """Make selection behavior more like traditional Burp"""
        # Use a more persistent selection model
        self.log_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        
        # Make selection more visible
        self.log_table.setSelectionBackground(Color(64, 114, 196))
        self.log_table.setSelectionForeground(Color.WHITE)
        
        # Don't clear selection on focus loss
        self.log_table.setFocusable(True)

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
        
        # SET COLUMN WIDTHS
        column_model = self.log_table.getColumnModel()
        
        # Set preferred widths for each column
        column_model.getColumn(0).setPreferredWidth(40)   # No. - Small
        column_model.getColumn(1).setPreferredWidth(100)  # Screen Name - Medium
        column_model.getColumn(2).setPreferredWidth(150)  # Screen URL - Medium
        column_model.getColumn(3).setPreferredWidth(100)  # Button Name - Medium
        column_model.getColumn(4).setPreferredWidth(60)   # Method - Small
        column_model.getColumn(5).setPreferredWidth(350)  # Transition URL - Larger
        column_model.getColumn(6).setPreferredWidth(60)   # Params - Small
        column_model.getColumn(7).setPreferredWidth(80)   # Status - Small
        column_model.getColumn(8).setPreferredWidth(60)   # Length - Small
        
        # Make the table auto-resize to fit the container
        self.log_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        
        # ADD COPY FUNCTIONALITY TO TRANSITION URL COLUMN
        copy_mouse_listener = CopyButtonMouseListener(self)
        self.log_table.addMouseMotionListener(copy_mouse_listener)
        self.log_table.addMouseListener(copy_mouse_listener)
        
        # Set Burp Suite style selection colors
        self.log_table.setShowGrid(True)
        self.log_table.setGridColor(Color.LIGHT_GRAY)
        self.log_table.setSelectionBackground(Color(64, 114, 196))
        self.log_table.setSelectionForeground(Color.WHITE)
        self.log_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
            
        # Initialize control buttons
        self._setup_control_buttons()
        self._make_selection_more_visible()
        self._setup_persistent_selection()

        # Rest of your existing code...
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
            # Convert visual row index to model row index
            model_row = self.log_table.convertRowIndexToModel(selected_rows[0])
            
            # Use the mapping to get the actual request index
            if (hasattr(self, '_display_to_request_map') and 
                model_row < len(self._display_to_request_map)):
                
                actual_request_index = self._display_to_request_map[model_row]
                
                if actual_request_index < len(self.requests):
                    request_data = self.requests[actual_request_index]
                    
                    # Set request (isRequest=True)
                    request_bytes = request_data['messageInfo'].getRequest()
                    if request_bytes:
                        self._request_viewer.setMessage(request_bytes, True)
                    else:
                        # Create empty byte array instead of None
                        self._request_viewer.setMessage(bytearray(), True)
                    
                    # Set response (isRequest=False)
                    response = request_data['messageInfo'].getResponse()
                    if response:
                        self._response_viewer.setMessage(response, False)
                    else:
                        # Create empty byte array instead of None
                        self._response_viewer.setMessage(bytearray(), False)
                else:
                    # Clear with empty byte arrays instead of None
                    self._request_viewer.setMessage(bytearray(), True)
                    self._response_viewer.setMessage(bytearray(), False)
            else:
                # Clear with empty byte arrays instead of None
                self._request_viewer.setMessage(bytearray(), True)
                self._response_viewer.setMessage(bytearray(), False)
        else:
            # Clear when no row or multiple rows are selected with empty byte arrays
            self._request_viewer.setMessage(bytearray(), True)
            self._response_viewer.setMessage(bytearray(), False)

    def _save_table_edits(self):
        """Save user edits from the table back to the requests data"""
        if not hasattr(self, '_display_to_request_map'):
            return
            
        for row in range(self.log_model.getRowCount()):
            if row < len(self._display_to_request_map):
                actual_index = self._display_to_request_map[row]
                if actual_index < len(self.requests):
                    # Get values from table model
                    screen_name = self.log_model.getValueAt(row, 1)  # Column 1: Screen Name
                    screen_url = self.log_model.getValueAt(row, 2)   # Column 2: Screen URL  
                    button_name = self.log_model.getValueAt(row, 3)  # Column 3: Button Name
                    
                    # Save to actual request data
                    if screen_name is not None:
                        self.requests[actual_index]['screen_name'] = str(screen_name)
                    if screen_url is not None:
                        self.requests[actual_index]['screen_url'] = str(screen_url)
                    if button_name is not None:
                        self.requests[actual_index]['button_name'] = str(button_name)


    def _refresh_display(self, event=None):
        """Force refresh the display to sync with actual data"""
        
        # SAVE USER EDITS BEFORE REFRESHING
        self._save_table_edits()
        
        # Force update the display
        self._update_display()
        self._update_status()
        
        # Show confirmation
        visible_count = self.log_model.getRowCount()
        total_count = len(self.requests)
        
        if visible_count == 0 and total_count > 0:
            self.status_label.setText("Refreshed: {} total requests ({} filtered out)".format(
                total_count, total_count - visible_count))
        else:
            self.status_label.setText("Refreshed: {} requests displayed".format(visible_count))


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
        self.duplicate_button = JButton("Hide Duplicates", actionPerformed=self._toggle_duplicates)
        self.refresh_button = JButton("Refresh Display", actionPerformed=self._refresh_display)
        self.status_label = JLabel("Ready. 0 requests captured")
        
        # ADD REFRESH BUTTON
        self.refresh_button = JButton("Refresh Display", actionPerformed=self._refresh_display)
        
        self.status_label = JLabel("Ready. 0 requests captured")

    def _toggle_duplicates(self, event):
        """Toggle between hiding and showing duplicate requests"""
        self._hide_duplicates = not self._hide_duplicates
        
        if self._hide_duplicates:
            self.duplicate_button.setText("Show Duplicates")
            self.duplicate_button.setBackground(Color(100, 200, 100))  # Green when active
            self.duplicate_button.setForeground(Color.WHITE)
        else:
            self.duplicate_button.setText("Hide Duplicates") 
            self.duplicate_button.setBackground(None)  # Default color
            self.duplicate_button.setForeground(None)
        
        # Update the display to apply the filter
        self._update_display()
        
        # Show brief status message
        if self._hide_duplicates:
            self.status_label.setText("Hiding duplicate requests")
        else:
            self.status_label.setText("Showing all requests (including duplicates)")


    def _export_to_excel(self, event):
        # First, filter requests using the same logic as _update_display
        filtered_requests = []
        
        for req in self.requests:
            # Check scope
            try:
                url = req['messageInfo'].getUrl()
                if not self._check_custom_scope(url):
                    continue  # Skip if not in scope
            except:
                # If URL can't be parsed, skip this request
                continue
                
            # Check file extension filters
            if not self._should_display(req):
                continue  # Skip if filtered by extension
                
            # If we get here, the request passed both filters
            filtered_requests.append(req)
        
        if not filtered_requests:
            JOptionPane.showMessageDialog(None,
                "No filtered data to export",
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
            
            # In your _export_to_excel method, replace the writing part with:
            try:
                # Use UTF-8 with BOM for better Excel compatibility with Japanese
                with open(file_path, 'wb') as csvfile:
                    # Write UTF-8 BOM for Excel compatibility
                    csvfile.write('\ufeff'.encode('utf-8'))
                    
                    writer = csv.writer(csvfile)
                    
                    # Write headers
                    headers = [
                        "No.", "Screen Name", "Screen URL", "Button Name", 
                        "Method", "Transition URL", "Params", "Status", "Length"
                    ]
                    writer.writerow(headers)
                    
                    # Export data from the TABLE MODEL (includes user edits)
                    for row in range(self.log_model.getRowCount()):
                        row_data = []
                        for col in range(self.log_model.getColumnCount()):
                            value = self.log_model.getValueAt(row, col)
                            # Handle encoding for export
                            if value is not None:
                                try:
                                    # Ensure proper encoding for export
                                    if isinstance(value, str):
                                        # Normalize the string - encode to bytes then decode back
                                        encoded_value = value.encode('utf-8', 'replace').decode('utf-8')
                                        row_data.append(encoded_value)
                                    else:
                                        row_data.append(str(value))
                                except:
                                    row_data.append("[Encoding Error]")
                            else:
                                row_data.append("")
                        # Encode each row to UTF-8 before writing
                        encoded_row = [cell.encode('utf-8') if isinstance(cell, unicode) else str(cell) for cell in row_data]
                        writer.writerow(encoded_row)
                
                JOptionPane.showMessageDialog(None,
                    "Exported {} filtered requests to:\n{}".format(self.log_model.getRowCount(), file_path),
                    "Export Successful",
                    JOptionPane.INFORMATION_MESSAGE)
                    
            except Exception as e:
                JOptionPane.showMessageDialog(None,
                    "Export failed: {}".format(str(e)),
                    "Error",
                    JOptionPane.ERROR_MESSAGE)

    def _safe_string(self, value):
        """Safely convert value to string with proper encoding handling"""
        if value is None:
            return ""
        try:
            if isinstance(value, str):
                # Handle any encoding issues
                return value.encode('utf-8', 'replace').decode('utf-8')
            return str(value)
        except:
            return "[Encoding Error]"


    def _delete_selected(self, event=None):
        selected_rows = [self.log_table.convertRowIndexToModel(i) 
                        for i in self.log_table.getSelectedRows()]
        if not selected_rows:
            return

        confirm = JOptionPane.showConfirmDialog(
            None,
            "Delete {} selected requests?".format(len(selected_rows)),
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION)
        
        if confirm == JOptionPane.YES_OPTION:
            
            # Get the actual request indices using the mapping
            actual_indices_to_delete = []
            for row in selected_rows:
                if (hasattr(self, '_display_to_request_map') and 
                    row < len(self._display_to_request_map)):
                    actual_index = self._display_to_request_map[row]
                    actual_indices_to_delete.append(actual_index)
            
            if not actual_indices_to_delete:
                JOptionPane.showMessageDialog(None,
                    "No valid requests to delete",
                    "Delete Failed",
                    JOptionPane.WARNING_MESSAGE)
                return
            
            # Sort in reverse order for safe deletion
            actual_indices_to_delete.sort(reverse=True)
            
            # Save user edits BEFORE deletion
            self._save_table_edits()
            
            # Delete from self.requests using actual indices
            new_requests = []
            old_to_new_map = {}
            new_number = 1
            
            deleted_count = 0
            for i, req in enumerate(self.requests):
                if i not in actual_indices_to_delete:
                    old_number = req['number']
                    req['number'] = new_number
                    old_to_new_map[old_number] = new_number
                    new_requests.append(req)
                    new_number += 1
                else:
                    deleted_count += 1
            
            self.requests = new_requests
            
            # Migrate highlights
            self.highlight_renderer.migrateHighlights(old_to_new_map)
            
            # Update display and status WITHOUT going blank
            self._update_display()
            self._update_status()
            
            # Clear viewers with empty byte arrays instead of None
            self._request_viewer.setMessage(bytearray(), True)
            self._response_viewer.setMessage(bytearray(), False)
            
            # Show success message
            JOptionPane.showMessageDialog(
                None,
                "Successfully deleted {} requests".format(deleted_count),
                "Delete Successful",
                JOptionPane.INFORMATION_MESSAGE
            )


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
        
        # Use the display-to-request mapping to get the actual request
        if (hasattr(self, '_display_to_request_map') and 
            row < len(self._display_to_request_map)):
            
            actual_request_index = self._display_to_request_map[row]
            
            if actual_request_index < len(self.requests):
                req_data = self.requests[actual_request_index]
                
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
        else:
            JOptionPane.showMessageDialog(None,
                "Could not find the selected request",
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
        try:
            # Store current selection by REQUEST NUMBER (not index)
            selected_request_numbers = set()
            
            # Store current scroll position
            scroll_position = None
            selected_row_rect = None
            
            if hasattr(self, '_display_to_request_map') and self.log_table.getRowCount() > 0:
                # Store selected rows by their request number (the value in column 0)
                for view_row in self.log_table.getSelectedRows():
                    model_row = self.log_table.convertRowIndexToModel(view_row)
                    if model_row < self.log_model.getRowCount():
                        request_number_value = self.log_model.getValueAt(model_row, 0)
                        if request_number_value:
                            # Extract the actual number (handle asterisks for duplicates)
                            try:
                                if isinstance(request_number_value, str):
                                    clean_value = request_number_value.replace('*', '').strip()
                                    if clean_value.isdigit():
                                        selected_request_numbers.add(int(clean_value))
                                else:
                                    selected_request_numbers.add(int(request_number_value))
                            except:
                                pass
                
                # Store the scroll position based on the FIRST selected row
                if selected_request_numbers:
                    for view_row in range(self.log_table.getRowCount()):
                        model_row = self.log_table.convertRowIndexToModel(view_row)
                        if model_row < self.log_model.getRowCount():
                            request_number_value = self.log_model.getValueAt(model_row, 0)
                            if request_number_value:
                                try:
                                    if isinstance(request_number_value, str):
                                        clean_value = request_number_value.replace('*', '').strip()
                                        if clean_value.isdigit() and int(clean_value) in selected_request_numbers:
                                            selected_row_rect = self.log_table.getCellRect(view_row, 0, False)
                                            scroll_position = self.log_table.getVisibleRect()
                                            break
                                except:
                                    pass
            
            # Store current highlights
            current_highlights = self.highlight_renderer.highlight_colors.copy()
            
            # Save user edits BEFORE updating display
            self._save_table_edits()
            
            # DON'T clear the table completely - update rows intelligently
            current_row_count = self.log_model.getRowCount()
            
            # Track seen URLs AND methods to detect duplicates
            seen_requests = {}
            display_counter = 1
            
            # Create new mapping between display rows and actual request indices
            new_display_to_request_map = []
            
            # Build list of requests that should be displayed
            display_requests = []
            seen_requests_set = set()

            for req_index, req in enumerate(self.requests):
                # Check scope
                try:
                    url = req['messageInfo'].getUrl()
                    if not self._check_custom_scope(url):
                        continue
                except:
                    continue
                    
                # Check file extension filters
                if not self._should_display(req):
                    continue
                if self._hide_duplicates:
                    actual_url = req['messageInfo'].getUrl().toString()
                    method = req['method']
                    request_key = (actual_url, method)
                    
                    if request_key in seen_requests_set:
                        continue  # Skip this duplicate request
                    else:
                        seen_requests_set.add(request_key)

                display_requests.append((req_index, req))
            
            # Track seen URLs AND methods to detect duplicates (for asterisk marking)
            seen_requests = {}
            display_counter = 1

            # Create new mapping between display rows and actual request indices
            new_display_to_request_map = []

            # Update table rows - only modify what changed
            displayed_count = 0
            
            for req_index, req in display_requests:
                # Check for duplicates (for visual marking with asterisk)
                actual_url = req['messageInfo'].getUrl().toString()
                method = req['method']
                request_key = (actual_url, method)
                
                display_number = display_counter
                display_counter += 1
                
                # Only mark with asterisk if we're showing duplicates
                if not self._hide_duplicates and request_key in seen_requests:
                    first_occurrence = seen_requests[request_key]
                    display_number = "{}*".format(first_occurrence)
                else:
                    seen_requests[request_key] = display_number
                
                new_display_to_request_map.append(req_index)
                
                # Prepare row data with proper encoding handling
                status = str(req.get('status', "Pending"))
                if status.isdigit():
                    status_code = int(status)
                    if 200 <= status_code < 300:
                        status = "%s (OK)" % status_code
                    elif status_code >= 400:
                        status = "%s (Error)" % status_code
                
                # Safely encode all string values to handle non-ASCII characters
                def safe_encode(value):
                    if value is None:
                        return ""
                    try:
                        if isinstance(value, str):
                            # Encode to UTF-8 and decode back to handle any encoding issues
                            return value.encode('utf-8', 'replace').decode('utf-8')
                        return str(value)
                    except:
                        return "[Encoding Error]"
                
                row_data = [
                    safe_encode(display_number),
                    safe_encode(req.get('screen_name', "")),
                    safe_encode(req.get('screen_url', "")),
                    safe_encode(req.get('button_name', "")),
                    safe_encode(method),
                    safe_encode(req.get('transition_url', "")),
                    safe_encode(req.get('params', 0)),
                    safe_encode(status),
                    safe_encode(req.get('length', 0))
                ]
                
                # Update or add row
                if displayed_count < current_row_count:
                    # Update existing row
                    for col, value in enumerate(row_data):
                        self.log_model.setValueAt(value, displayed_count, col)
                else:
                    # Add new row
                    self.log_model.addRow(row_data)
                
                displayed_count += 1
            
            # Remove extra rows if we have fewer displayed requests than before
            while self.log_model.getRowCount() > displayed_count:
                self.log_model.removeRow(self.log_model.getRowCount() - 1)
            
            # Update the mapping
            self._display_to_request_map = new_display_to_request_map
            
            # Restore highlights
            self.highlight_renderer.highlight_colors = current_highlights
            
            # RESTORE SELECTION BY REQUEST NUMBER
            if selected_request_numbers:
                self.log_table.clearSelection()
                selection_restored = False
                
                for view_row in range(min(len(self._display_to_request_map), self.log_model.getRowCount())):
                    # Get the request number from column 0
                    request_number_value = self.log_model.getValueAt(view_row, 0)
                    if request_number_value:
                        try:
                            # Extract the actual number (handle asterisks for duplicates)
                            if isinstance(request_number_value, str):
                                clean_value = request_number_value.replace('*', '').strip()
                                if clean_value.isdigit():
                                    req_num = int(clean_value)
                                else:
                                    continue
                            else:
                                req_num = int(request_number_value)
                            
                            # Select if this request number was previously selected
                            if req_num in selected_request_numbers:
                                self.log_table.addRowSelectionInterval(view_row, view_row)
                                selection_restored = True
                                
                        except Exception as e:
                            continue
            
            # Force UI refresh
            self.log_table.repaint()
            
        except Exception as e:
            print "[ERROR] _update_display failed: {}".format(str(e))
            import traceback
            traceback.print_exc()

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
                'messageInfo': messageInfo,
                'request_hash': hash(messageInfo.getRequest().tostring())
            }
            self.requests.append(entry)
            
            # Update status immediately
            self._update_status()
            
            # Only update display periodically to reduce flickering
            # Update more frequently when table is small, less when large
            total_requests = len(self.requests)
            if total_requests < 50:
                update_frequency = 3  # Update every 3 requests
            elif total_requests < 200:
                update_frequency = 5  # Update every 5 requests
            else:
                update_frequency = 10  # Update every 10 requests
                
            if total_requests % update_frequency == 0 or total_requests < 10:
                self._update_display()
            
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
                        req['messageInfo'] = messageInfo
                        
                        # Update display for status changes, but less frequently
                        if len(self.requests) % 5 == 0:
                            self._update_display()
                        break
            
            self._update_status()


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
        control_panel.add(self.duplicate_button)
        control_panel.add(self.refresh_button) 
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
        else:
            self.pause_button.setText("Pause Logging")
            # Simply clear any pending requests without asking
            self._pending_requests = []
            self._update_status()

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

    def _check_custom_scope(self, url):
        # If no scope rules defined, include everything
        if not self._custom_scope_rules:
            return True
        
        try:
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
                        domain_to_match = rule_host[2:]  # Remove "*." part
                        if not host.endswith(domain_to_match):
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
                        
                return True
            return False
            
        except Exception as e:
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
                rule[0] or "any",
                rule[1] or "any-host",
                rule[2] or "any-port", 
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
        dialog.setTitle("Filter by File Extension and Directory")
        dialog.setSize(600, 500)
        dialog.setLayout(BorderLayout())
        dialog.setModal(True)

        # Main content panel with tabbed interface
        tabbed_pane = JTabbedPane()

        # TAB 1: Extension Filters
        extension_panel = JPanel(BorderLayout(10, 10))

        # PRESET SELECTION PANEL
        preset_panel = JPanel(BorderLayout(5, 5))
        preset_panel.add(JLabel("Quick Presets:"), BorderLayout.NORTH)
        self.preset_combo = JComboBox(["Custom", "Basic Filter", "Comprehensive Filter", "Minimal Filter", "Security Focus Only"])
        self.preset_combo.addActionListener(lambda e: self._apply_preset_filter())
        preset_panel.add(self.preset_combo, BorderLayout.CENTER)

        # Extension Input Panel
        extension_input_panel = JPanel(GridLayout(4, 1, 5, 5))

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

        extension_input_panel.add(include_panel)
        extension_input_panel.add(exclude_panel)

        # Info label
        info_label = JLabel("Note: Include filter has priority over exclude filter")
        info_label.setForeground(Color.GRAY)

        # Assembly for extension tab
        extension_panel.add(preset_panel, BorderLayout.NORTH)
        extension_panel.add(extension_input_panel, BorderLayout.CENTER)
        extension_panel.add(info_label, BorderLayout.SOUTH)

        # TAB 2: Directory Filters
        directory_panel = JPanel(BorderLayout(10, 10))

        # Directory Input Panel
        directory_input_panel = JPanel(GridLayout(4, 1, 5, 5))

        # Include Directories
        include_dir_panel = JPanel(BorderLayout())
        include_dir_panel.add(JLabel("Show ONLY URLs containing these paths (comma separated):"), BorderLayout.NORTH)
        self.include_dir_field = JTextField(",".join(self._include_directories))
        include_dir_panel.add(self.include_dir_field, BorderLayout.CENTER)
        include_dir_panel.add(JLabel("Example: /wp-content/, /api/, /admin/"), BorderLayout.SOUTH)

        # Exclude Directories
        exclude_dir_panel = JPanel(BorderLayout())
        exclude_dir_panel.add(JLabel("HIDE URLs containing these paths (comma separated):"), BorderLayout.NORTH)
        self.exclude_dir_field = JTextField(",".join(self._exclude_directories))
        exclude_dir_panel.add(self.exclude_dir_field, BorderLayout.CENTER)
        exclude_dir_panel.add(JLabel("Example: /wp-content/, /static/, /images/"), BorderLayout.SOUTH)

        directory_input_panel.add(include_dir_panel)
        directory_input_panel.add(exclude_dir_panel)

        # Directory Info
        dir_info_label = JLabel("Note: Directory paths are case-sensitive. Use partial paths like /wp-content/ to match all subdirectories.")
        dir_info_label.setForeground(Color.GRAY)

        # Assembly for directory tab
        directory_panel.add(JLabel("Directory-based Filtering", JLabel.CENTER), BorderLayout.NORTH)
        directory_panel.add(directory_input_panel, BorderLayout.CENTER)
        directory_panel.add(dir_info_label, BorderLayout.SOUTH)

        # Add tabs to tabbed pane
        tabbed_pane.addTab("Extensions", extension_panel)
        tabbed_pane.addTab("Directories", directory_panel)

        # Button Panel
        button_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        apply_btn = JButton("Apply All Filters", actionPerformed=lambda e: self._apply_all_filters(dialog))
        button_panel.add(apply_btn)

        cancel_btn = JButton("Cancel", actionPerformed=lambda e: dialog.dispose())
        button_panel.add(cancel_btn)

        clear_btn = JButton("Clear All Filters", actionPerformed=lambda e: self._clear_all_filters())
        button_panel.add(clear_btn)

        # Assembly
        dialog.add(tabbed_pane, BorderLayout.CENTER)
        dialog.add(button_panel, BorderLayout.SOUTH)
        dialog.setLocationRelativeTo(None)
        dialog.setVisible(True)

    def _apply_all_filters(self, dialog):
        """Apply both extension and directory filters"""
        # Process extension filters
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

        # Process directory filters
        include_dir_text = self.include_dir_field.getText().strip()
        exclude_dir_text = self.exclude_dir_field.getText().strip()

        # Process include directories
        self._include_directories = []
        if include_dir_text:
            directories = [dir_path.strip() for dir_path in include_dir_text.split(",") if dir_path.strip()]
            for dir_path in directories:
                # Ensure directory path starts with / for consistency
                if not dir_path.startswith('/'):
                    dir_path = '/' + dir_path
                self._include_directories.append(dir_path)

        # Process exclude directories
        self._exclude_directories = []
        if exclude_dir_text:
            directories = [dir_path.strip() for dir_path in exclude_dir_text.split(",") if dir_path.strip()]
            for dir_path in directories:
                # Ensure directory path starts with / for consistency
                if not dir_path.startswith('/'):
                    dir_path = '/' + dir_path
                self._exclude_directories.append(dir_path)

        dialog.dispose()
        self._update_display()  # Refresh display with new filters

        # Update status to show active filters
        total_filters = (len(self._include_extensions) + len(self._exclude_extensions) +
                        len(self._include_directories) + len(self._exclude_directories))

        if total_filters > 0:
            self.status_label.setText("Applied {} filter rules".format(total_filters))

    def _clear_all_filters(self):
        """Clear all extension and directory filters"""
        self._include_extensions = []
        self._exclude_extensions = []
        self._include_directories = []
        self._exclude_directories = []
        self._update_display()
        self.status_label.setText("All filters cleared")

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

#    def _clear_filters(self):
#        """Clear all extension filters"""
#        self._include_extensions = []
#        self._exclude_extensions = []
#        self._update_display()

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

    def _should_display(self, entry):
        # Use the actual URL from the messageInfo
        try:
            url = entry['messageInfo'].getUrl().toString()
            url_path = entry['messageInfo'].getUrl().getPath() or ""
        except:
            url = entry.get('screen_url', '')
            url_path = ""

        # Check include directories (if any are specified)
        if self._include_directories:
            has_include_dir = False
            for dir_path in self._include_directories:
                # Check if the URL path contains the directory path
                if dir_path in url_path:
                    has_include_dir = True
                    break
            if not has_include_dir:
                return False

        # Check exclude directories (if any are specified)
        if self._exclude_directories:
            for dir_path in self._exclude_directories:
                # Check if the URL path contains the directory path
                if dir_path in url_path:
                    return False

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
        
        # Calculate unique requests count
        unique_requests = set()
        for req in self.requests:
            try:
                url = req['messageInfo'].getUrl().toString()
                method = req['method']
                unique_requests.add((url, method))
            except:
                pass
        
        total_requests = len(self.requests)
        unique_count = len(unique_requests)
        duplicate_count = total_requests - unique_count
        
        status_text = "Captured: {} requests ({} unique, {} duplicates)".format(
            total_requests, unique_count, duplicate_count)
        
        if pending_count > 0:
            status_text += " | {} pending".format(pending_count)
        
        status_text += " | Last: {}".format(datetime.now().strftime("%H:%M:%S"))
        
        # Add duplicate filter status
        if self._hide_duplicates:
            status_text += " | Duplicates: HIDDEN"
        else:
            status_text += " | Duplicates: SHOWN"
        
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

