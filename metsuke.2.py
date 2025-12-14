# -*- coding: utf-8 -*-

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
from javax.swing import JMenu  
from java.awt import Toolkit 
from javax.swing import ListSelectionModel 
from javax.swing import JCheckBox  
from javax.swing import JSplitPane
from burp import IMessageEditor
from javax.swing import JButton, AbstractCellEditor
from java.awt.event import ActionListener, MouseAdapter
from java.awt import Cursor
from burp import IBurpExtender, IHttpListener, ITab, IMessageEditorController
from javax.swing import Timer
from java.awt.event import MouseEvent
import re
import htmlentitydefs
import urllib


HIGHLIGHT_COLORS = {
    "Red": Color(255, 100, 100),
    "Grey": Color(200, 200, 200),
    "Yellow": Color(255, 255, 150),
    "Pink": Color(255, 150, 200)
}

class HighlightRenderer(DefaultTableCellRenderer):
    def __init__(self):
        DefaultTableCellRenderer.__init__(self)
        self.highlight_colors = {} 
        self.dark_bg = Color(50, 50, 50)
        self.light_bg = Color.WHITE
        
        
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        

        model_row = table.convertRowIndexToModel(row)
        
   
        display_value = table.getModel().getValueAt(model_row, 0)
        
   
        try:
            if isinstance(display_value, str):
                clean_value = display_value.replace('*', '').strip()
                if clean_value.isdigit():
                    req_no = int(clean_value)
                else:
                    req_no = None
            else:
                req_no = int(display_value)
        except:
            req_no = None
        
        bg_color = table.getBackground()
        is_dark = bg_color.getRed() < 128
        
        if is_dark:
            default_fg = Color.WHITE
            default_bg = self.dark_bg
            highlight_fg = Color.BLACK
        else:
            default_fg = Color.BLACK
            default_bg = self.light_bg
            highlight_fg = Color.WHITE
        
        component.setForeground(default_fg)
        if not isSelected:
            component.setBackground(default_bg)
        
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
        
        if column == 5 and row >= 0:
            table.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        else:
            table.setCursor(Cursor.getDefaultCursor())
            
    def mouseClicked(self, event):
        if event.getClickCount() != 1:
            return
            
        table = event.getSource()
        point = event.getPoint()
        row = table.rowAtPoint(point)
        column = table.columnAtPoint(point)
        
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


class TableDragDropListener(MouseAdapter):
    def __init__(self, extender, table):
        self.extender = extender
        self.table = table
        self.dragged_row = None
        self.pressed_point = None
        self.is_dragging = False
    
    def mousePressed(self, event):
        # Only handle left clicks
        if event.getButton() != MouseEvent.BUTTON1:
            return
            
        point = event.getPoint()
        row = self.table.rowAtPoint(point)
        column = self.table.columnAtPoint(point)
        
        # ONLY start drag on "No." column (column 0)
        if column != 0:
            return
            
        if row >= 0:
            self.dragged_row = row
            self.pressed_point = point
            self.is_dragging = True
            self.table.setCursor(Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR))
    
    def mouseDragged(self, event):
        if self.is_dragging and self.dragged_row is not None:
            # Change cursor to indicate dragging
            self.table.setCursor(Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR))
    
    def mouseReleased(self, event):
        # Only handle left clicks
        if event.getButton() != MouseEvent.BUTTON1 or not self.is_dragging:
            self.is_dragging = False
            return
            
        if self.dragged_row is not None:
            point = event.getPoint()
            target_row = self.table.rowAtPoint(point)
            
            # Only move if we're on a different valid row
            if target_row >= 0 and target_row != self.dragged_row:
                self._move_row(self.dragged_row, target_row)
            
            self._cleanup_drag()
    
    def _cleanup_drag(self):
        """Clean up drag state"""
        self.dragged_row = None
        self.pressed_point = None
        self.is_dragging = False
        self.table.setCursor(Cursor.getDefaultCursor())
    
    def _move_row(self, from_index, to_index):
        # Convert visual indices to model indices
        from_model = self.table.convertRowIndexToModel(from_index)
        to_model = self.table.convertRowIndexToModel(to_index)
        
        self.extender._save_table_edits()
        
        # Get the actual request indices from the mapping
        if (hasattr(self.extender, '_display_to_request_map') and 
            from_model < len(self.extender._display_to_request_map) and 
            to_model < len(self.extender._display_to_request_map)):
            
            actual_from_index = self.extender._display_to_request_map[from_model]
            actual_to_index = self.extender._display_to_request_map[to_model]
            
            # Move the request in the actual requests list
            if (actual_from_index < len(self.extender.requests) and 
                actual_to_index < len(self.extender.requests)):
                
                request_to_move = self.extender.requests[actual_from_index]
                
                self.extender.requests.pop(actual_from_index)
                
                new_position = actual_to_index
                
                if actual_from_index < actual_to_index:
                    new_position = actual_to_index
                else:
                    new_position = actual_to_index
                
                # Insert at new position
                self.extender.requests.insert(new_position, request_to_move)
                
                self.extender._update_display_after_reorder()
                
                # Select the moved row
                self.table.clearSelection()
                visual_target_row = -1
                
                # Find the visual row that corresponds to the moved request
                for visual_row in range(self.table.getRowCount()):
                    model_row = self.table.convertRowIndexToModel(visual_row)
                    if (model_row < len(self.extender._display_to_request_map) and 
                        self.extender._display_to_request_map[model_row] == new_position):
                        visual_target_row = visual_row
                        break
                
                if visual_target_row >= 0:
                    self.table.addRowSelectionInterval(visual_target_row, visual_target_row)


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
        self._exclude_directories = []  
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

    def _setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts for the table"""
        # Create input map and action map for keyboard shortcuts
        input_map = self.log_table.getInputMap(JTable.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
        action_map = self.log_table.getActionMap()
        
        # Ctrl+R - Send to Repeater
        input_map.put(self._get_keystroke("ctrl R"), "sendToRepeater")
        action_map.put("sendToRepeater", self._create_key_action(lambda: self._view_in_repeater()))
        
        # Ctrl+C - Copy selected rows
        input_map.put(self._get_keystroke("ctrl C"), "copyRows")
        action_map.put("copyRows", self._create_key_action(lambda: self._copy_selected()))
        
        # Tab - Move to next row (same column)
        input_map.put(self._get_keystroke("TAB"), "tabNextRow")
        action_map.put("tabNextRow", self._create_key_action(lambda: self._tab_to_next_row()))
        
        # Shift+Tab - Move to previous row (same column)
        input_map.put(self._get_keystroke("shift TAB"), "tabPrevRow")
        action_map.put("tabPrevRow", self._create_key_action(lambda: self._tab_to_previous_row()))

    def _get_keystroke(self, key_string):
        """Helper to create keystroke from string"""
        from javax.swing import KeyStroke
        return KeyStroke.getKeyStroke(key_string)

    def _create_key_action(self, action_function):
        """Helper to create action from function"""
        from javax.swing import AbstractAction
        class KeyAction(AbstractAction):
            def __init__(self, function):
                super(KeyAction, self).__init__()
                self.function = function
            def actionPerformed(self, event):
                self.function()
        return KeyAction(action_function)

    def _tab_to_next_row(self):
        """Move to next row when Tab is pressed in editable cells"""
        selected_rows = self.log_table.getSelectedRows()
        if not selected_rows:
            return
        
        current_row = selected_rows[0]
        current_col = self.log_table.getSelectedColumn()
        
        # If we're not on the last row, move to next row
        if current_row < self.log_table.getRowCount() - 1:
            next_row = current_row + 1
            self.log_table.clearSelection()
            self.log_table.setRowSelectionInterval(next_row, next_row)
            self.log_table.setColumnSelectionInterval(current_col, current_col)
            
            # Ensure the new row is visible
            self.log_table.scrollRectToVisible(self.log_table.getCellRect(next_row, current_col, True))

    def _tab_to_previous_row(self):
        """Move to previous row when Shift+Tab is pressed in editable cells"""
        selected_rows = self.log_table.getSelectedRows()
        if not selected_rows:
            return
        
        current_row = selected_rows[0]
        current_col = self.log_table.getSelectedColumn()
        
        # If we're not on the first row, move to previous row
        if current_row > 0:
            prev_row = current_row - 1
            self.log_table.clearSelection()
            self.log_table.setRowSelectionInterval(prev_row, prev_row)
            self.log_table.setColumnSelectionInterval(current_col, current_col)
            
            # Ensure the new row is visible
            self.log_table.scrollRectToVisible(self.log_table.getCellRect(prev_row, current_col, True))


    def registerExtenderCallbacks(self, callbacks):
        # Force UTF-8 encoding for Japanese text support
        import sys
        reload(sys)
        sys.setdefaultencoding('utf-8')
        
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Metsuke")
        callbacks.registerHttpListener(self)
        
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
            "Method", "Transition URL", "Params", "Status", "Length", "Remarks"
        ]
        self.log_model = DefaultTableModel()
        self.log_model.setColumnIdentifiers(column_names)
        self.log_table = JTable(self.log_model)
        self.log_model = DefaultTableModel()
        self.log_model.setColumnIdentifiers(column_names)
        self.log_table = JTable(self.log_model)
        
        # Initialize renderer
        self.highlight_renderer = HighlightRenderer()
        self.log_table.setDefaultRenderer(Object, self.highlight_renderer)
        self._setup_keyboard_shortcuts()

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
        column_model.getColumn(9).setPreferredWidth(100)
        
        # Make the table auto-resize to fit the container
        self.log_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        
        # ADD COPY FUNCTIONALITY TO TRANSITION URL COLUMN
        copy_mouse_listener = CopyButtonMouseListener(self)
        self.log_table.addMouseMotionListener(copy_mouse_listener)
        self.log_table.addMouseListener(copy_mouse_listener)
        
        # ADD DRAG AND DROP FUNCTIONALITY - ADD THESE LINES
        drag_drop_listener = TableDragDropListener(self, self.log_table)
        self.log_table.addMouseListener(drag_drop_listener)
        self.log_table.addMouseMotionListener(drag_drop_listener)
        
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

        # ... rest of your existing _init_ui_components code ...

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
        # Create text fields that support Japanese input
        japanese_text_field = JTextField()
        
        self.log_table.getColumnModel().getColumn(1).setCellEditor(  # Screen Name
            DefaultCellEditor(japanese_text_field))
        self.log_table.getColumnModel().getColumn(3).setCellEditor(  # Button Name
            DefaultCellEditor(JTextField()))
        self.log_table.getColumnModel().getColumn(4).setCellEditor(  # Method
            DefaultCellEditor(JTextField()))
        self.log_table.getColumnModel().getColumn(9).setCellEditor(  # YOUR_NEW_COLUMN
            DefaultCellEditor(JTextField()))


    def _update_display_after_reorder(self):
        """Update display after drag and drop reordering"""
        # Rebuild the display mapping based on current requests order
        self._display_to_request_map = list(range(len(self.requests)))
        
        # Update the table display
        self._update_display()
        
        # Show brief status message
        self.status_label.setText("Row order updated - drag & drop applied")


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
        """Save user edits from the table back to the requests data with proper encoding"""
        if not hasattr(self, '_display_to_request_map'):
            return
            
        for row in range(self.log_model.getRowCount()):
            if row < len(self._display_to_request_map):
                actual_index = self._display_to_request_map[row]
                if actual_index < len(self.requests):
                    # Get values from table model and preserve Japanese text as Unicode
                    screen_name = self.log_model.getValueAt(row, 1)  # Column 1: Screen Name
                    screen_url = self.log_model.getValueAt(row, 2)   # Column 2: Screen URL  
                    button_name = self.log_model.getValueAt(row, 3)  # Column 3: Button Name
                    new_field_value = self.log_model.getValueAt(row, 9)
                    
                    # Store as Unicode strings, not encoded bytes
                    if new_field_value is not None:
                        try:
                            if isinstance(new_field_value, unicode):
                                self.requests[actual_index]['YOUR_NEW_FIELD'] = new_field_value
                            else:
                                # Convert to Unicode
                                self.requests[actual_index]['YOUR_NEW_FIELD'] = unicode(str(new_field_value))
                        except:
                            self.requests[actual_index]['YOUR_NEW_FIELD'] = unicode(str(new_field_value))                    

                    # Save to actual request data as Unicode strings
                    if screen_name is not None:
                        try:
                            if isinstance(screen_name, unicode):
                                self.requests[actual_index]['screen_name'] = screen_name
                            else:
                                self.requests[actual_index]['screen_name'] = unicode(str(screen_name))
                        except:
                            self.requests[actual_index]['screen_name'] = unicode(str(screen_name))
                    
                    if screen_url is not None:
                        try:
                            if isinstance(screen_url, unicode):
                                self.requests[actual_index]['screen_url'] = screen_url
                            else:
                                self.requests[actual_index]['screen_url'] = unicode(str(screen_url))
                        except:
                            self.requests[actual_index]['screen_url'] = unicode(str(screen_url))
                    
                    if button_name is not None:
                        try:
                            if isinstance(button_name, unicode):
                                self.requests[actual_index]['button_name'] = button_name
                            else:
                                self.requests[actual_index]['button_name'] = unicode(str(button_name))
                        except:
                            self.requests[actual_index]['button_name'] = unicode(str(button_name))


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
        
        # Send to Repeater with shortcut hint
        send_to_repeater_item = JMenuItem("Send to Repeater (Ctrl+R)")
        send_to_repeater_item.addActionListener(lambda e: self._view_in_repeater())
        self.popup_menu.add(send_to_repeater_item)
        
        # Add separator
        self.popup_menu.addSeparator()
        
        # Auto-extract button name
        extract_item = JMenuItem("Try Extract Button Name")
        extract_item.addActionListener(lambda e: self._try_extract_button_manual())
        self.popup_menu.add(extract_item)
        # Clear button name
        clear_button_item = JMenuItem("Clear Button Name")
        clear_button_item.addActionListener(lambda e: self._clear_button_names())
        self.popup_menu.add(clear_button_item)

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
        
        # Copy with shortcut hint
        copy_item = JMenuItem("Copy (Ctrl+C)")
        copy_item.addActionListener(lambda e: self._copy_selected())
        self.popup_menu.add(copy_item)
        
        # Attach the popup menu to the table
        self.log_table.setComponentPopupMenu(self.popup_menu)

    def _clear_button_names(self):
        """Clear button names for selected rows"""
        selected_rows = [self.log_table.convertRowIndexToModel(i) 
                        for i in self.log_table.getSelectedRows()]
        if not selected_rows:
            return
        
        for row in selected_rows:
            if row < len(self._display_to_request_map):
                actual_index = self._display_to_request_map[row]
                if actual_index < len(self.requests):
                    self.log_model.setValueAt(u"", row, 3)  # Clear Button Name column
                    self.requests[actual_index]['button_name'] = u""


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
        self.export_button = JButton("Export", actionPerformed=self._export_to_excel)
        self.clear_button = JButton("Clear All", actionPerformed=self._confirm_clear)
        self.pause_button = JButton("Pause Logging", actionPerformed=self._toggle_pause)
        self.duplicate_button = JButton("Hide Duplicates", actionPerformed=self._toggle_duplicates)
        self.refresh_button = JButton("Refresh", actionPerformed=self._refresh_display)
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
                    continue
            except:
                # If URL can't be parsed, skip this request
                continue
                
            # Check file extension filters
            if not self._should_display(req):
                continue
                
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
            
            try:
                # Use pandas if available (better Excel compatibility)
                try:
                    import pandas as pd
                    use_pandas = True
                except:
                    use_pandas = False
                
                if use_pandas:
                    # Collect data into a list of lists
                    data = []
                    headers = ["No.", "Screen Name", "Screen URL", "Button Name", 
                            "Method", "Transition URL", "Params", "Status", "Length", "Remarks"]
                    
                    for row in range(self.log_model.getRowCount()):
                        row_data = []
                        for col in range(self.log_model.getColumnCount()):
                            value = self.log_model.getValueAt(row, col)
                            if value is None:
                                row_data.append('')
                            else:
                                if isinstance(value, unicode):
                                    row_data.append(value)
                                else:
                                    try:
                                        row_data.append(str(value).decode('utf-8'))
                                    except:
                                        row_data.append(unicode(str(value), errors='replace'))
                        data.append(row_data)
                    
                    # Create DataFrame and save with UTF-8 encoding
                    df = pd.DataFrame(data, columns=headers)
                    df.to_csv(file_path, index=False, encoding='utf-8-sig')  # utf-8-sig adds BOM
                else:
                    # Fallback to manual CSV writing
                    with open(file_path, 'wb') as f:
                        # Write UTF-8 BOM
                        f.write(b'\xef\xbb\xbf')
                        
                        # Write headers
                        headers = ["No.", "Screen Name", "Screen URL", "Button Name", 
                                "Method", "Transition URL", "Params", "Status", "Length", "Remarks"]
                        f.write(','.join(headers).encode('utf-8') + b'\n')
                        
                        # Write data
                        for row in range(self.log_model.getRowCount()):
                            row_data = []
                            for col in range(self.log_model.getColumnCount()):
                                value = self.log_model.getValueAt(row, col)
                                if value is None:
                                    cell = ''
                                else:
                                    if isinstance(value, unicode):
                                        cell = value
                                    else:
                                        try:
                                            cell = str(value).decode('utf-8')
                                        except:
                                            cell = unicode(str(value), errors='replace')
                                
                                # CSV escaping
                                cell = cell.replace('"', '""')
                                if ',' in cell or '"' in cell or '\n' in cell:
                                    cell = '"{}"'.format(cell)
                                row_data.append(cell)
                            
                            f.write(','.join(row_data).encode('utf-8') + b'\n')
                
                JOptionPane.showMessageDialog(None,
                    "Exported {} filtered requests to:\n{}".format(self.log_model.getRowCount(), file_path),
                    "Export Successful",
                    JOptionPane.INFORMATION_MESSAGE)
                    
            except Exception as e:
                import traceback
                traceback.print_exc()
                JOptionPane.showMessageDialog(None,
                    "Export failed: {}\n\n{}".format(str(e), traceback.format_exc()),
                    "Error",
                    JOptionPane.ERROR_MESSAGE)

    def _safe_string(self, value):
        """Safely convert value to string with proper encoding handling"""
        if value is None:
            return u""
        try:
            if isinstance(value, str):
                # Decode from UTF-8
                return value.decode('utf-8')
            elif isinstance(value, unicode):
                return value
            else:
                return unicode(str(value))
        except:
            return u"[Encoding Error]"


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
            
            # Reset the display mapping after deletion
            self._display_to_request_map = list(range(len(self.requests)))
            
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
                        "Request"
                    )
                    
                    # Switch to Repeater tab
                    try:
                        self._callbacks.activateBurpTab("Repeater")
                    except:
                        pass
                        
                    JOptionPane.showMessageDialog(None,
                        "Request sent to Repeater tab",
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
            
            # Add headers if multiple rows are selected
            if len(selected_rows) > 1:
                headers = []
                for col in range(self.log_model.getColumnCount()):
                    headers.append(str(self.log_model.getColumnName(col)))
                clipboard_data.append("\t".join(headers))
            
            for row in selected_rows:
                row_data = []
                for col in range(self.log_model.getColumnCount()):
                    value = self.log_model.getValueAt(row, col)
                    # Handle Japanese text properly
                    if value is not None:
                        try:
                            if isinstance(value, unicode):
                                row_data.append(value.encode('utf-8'))
                            else:
                                row_data.append(str(value))
                        except:
                            row_data.append(str(value) if value is not None else "")
                    else:
                        row_data.append("")
                clipboard_data.append("\t".join(row_data))

            from java.awt import Toolkit
            from java.awt.datatransfer import StringSelection
            toolkit = Toolkit.getDefaultToolkit()
            clipboard = toolkit.getSystemClipboard()
            clipboard.setContents(StringSelection("\n".join(clipboard_data)), None)

            # Show appropriate message based on number of rows copied
            if len(selected_rows) == 1:
                message = "Copied 1 row to clipboard."
            else:
                message = "Copied {} rows to clipboard (with headers).".format(len(selected_rows))
                
            # Show brief status instead of dialog to avoid interruption
            self.status_label.setText(message)
            
            # Auto-clear the status after 3 seconds
            def clear_status():
                self._update_status()
                
            timer = Timer(3000, lambda e: clear_status())
            timer.setRepeats(False)
            timer.start()

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
            
            # Check if we have a custom order (from drag & drop)
            has_custom_order = (hasattr(self, '_display_to_request_map') and 
                            len(self._display_to_request_map) == len(self.requests))
            
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

            # Use custom order if available from drag & drop, otherwise use original order
            request_indices = (self._display_to_request_map if has_custom_order 
                            else range(len(self.requests)))

            for req_index in request_indices:
                if req_index >= len(self.requests):
                    continue
                    
                req = self.requests[req_index]
                
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
                
                # Prepare row data with proper Japanese text handling
                status = str(req.get('status', "Pending"))
                if status.isdigit():
                    status_code = int(status)
                    if 200 <= status_code < 300:
                        status = "%s (OK)" % status_code
                    elif status_code >= 400:
                        status = "%s (Error)" % status_code

                # Handle Japanese text properly - don't re-encode if already unicode
                def safe_get_value(value, default=""):
                    if value is None:
                        return default
                    try:
                        # If it's already unicode, return as is
                        if isinstance(value, unicode):
                            return value
                        # If it's a string, decode from UTF-8
                        elif isinstance(value, str):
                            return value.decode('utf-8')
                        # Otherwise convert to string
                        else:
                            return unicode(str(value))
                    except:
                        return unicode(str(default))

                row_data = [
                    safe_get_value(display_number),
                    safe_get_value(req.get('screen_name', "")),
                    safe_get_value(req.get('screen_url', "")),
                    safe_get_value(req.get('button_name', "")),
                    safe_get_value(method),
                    safe_get_value(req.get('transition_url', "")),
                    safe_get_value(req.get('params', 0)),
                    safe_get_value(status),
                    safe_get_value(req.get('length', 0)),
                    safe_get_value(req.get('YOUR_NEW_FIELD', ""))  # Add this line
                ]
                
                # Update or add row
                if displayed_count < self.log_model.getRowCount():
                    # Update existing row - CHECK BOUNDS FIRST
                    if displayed_count < self.log_model.getRowCount():
                        for col, value in enumerate(row_data):
                            # Also check column bounds
                            if col < self.log_model.getColumnCount():
                                self.log_model.setValueAt(value, displayed_count, col)
                            else:
                                # This shouldn't happen, but add a fallback
                                print "[WARNING] Column index {} out of bounds".format(col)
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
            request_bytes = messageInfo.getRequest()
            
            # Initialize with empty button name
            button_name = u""
            
            # Create the entry
            entry = {
                'number': len(self.requests) + 1,
                'screen_url': u"",  # Unicode empty string
                'button_name': button_name,  # Start empty
                'method': analyzed.getMethod(),
                'transition_url': url_str,
                'params': self._get_parameters_count(analyzed),
                'status': "Pending",
                'length': 0,
                'YOUR_NEW_FIELD': u"",  # Remarks column - keep empty
                'messageInfo': messageInfo,
                'request_hash': hash(request_bytes.tostring()),
                'button_extraction_attempted': False,
                'request_url': url_str  # Store the request URL for later
            }
            
            self.requests.append(entry)
            self._update_status()
            
            if len(self.requests) % 3 == 0 or len(self.requests) < 10:
                self._update_display()
                
        else:
            # Process response...
            response = messageInfo.getResponse()
            if response:
                response_info = self._helpers.analyzeResponse(response)
                status_code = str(response_info.getStatusCode())
                response_length = len(response)
                
                # Find matching request
                request_hash = hash(messageInfo.getRequest().tostring())
                for req in self.requests:
                    if req.get('request_hash') == request_hash and req['status'] == "Pending":
                        req['status'] = status_code
                        req['length'] = response_length
                        req['messageInfo'] = messageInfo
                        
                        # Only try button extraction once per request
                        if not req.get('button_extraction_attempted', False):
                            # Try to extract button name with the request URL
                            request_bytes = messageInfo.getRequest()
                            request_url = req.get('request_url', '')
                            button_name = self._extract_button_from_response(response, request_url)
                            
                            if button_name:
                                req['button_name'] = button_name
                            
                            req['button_extraction_attempted'] = True
                        
                        # Update display
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


    def _extract_button_name_smart(self, request_bytes, response_bytes=None):
        """
        Smart button name extraction with multiple fallback strategies.
        Returns empty string if nothing meaningful is found.
        """
        if not request_bytes:
            return u""
        
        # Convert to string for analysis
        try:
            request_str = request_bytes.tostring() if hasattr(request_bytes, 'tostring') else str(request_bytes)
        except:
            return u""
        
        # Strategy 1: Look for form submission parameters (most reliable for POST)
        import re
        
        # Common submit button parameter names in multiple languages
        submit_param_patterns = [
            r'([^=&]+)=(Submit|送信|提出|実行|検索|ログイン|登録|確認|次へ|前へ|保存|削除|追加|更新|キャンセル|閉じる)',
            r'([^=&]+)=(submit|button|btn|commit|send|search|login|register|confirm|next|prev|save|delete|add|update|cancel|close)',
        ]
        
        # Check request body for form parameters
        for pattern in submit_param_patterns:
            matches = re.findall(pattern, request_str, re.IGNORECASE)
            for param_name, param_value in matches:
                # If we find a parameter that looks like a button value
                if param_value and len(param_value) < 50:  # Reasonable length for button text
                    return self._safe_unicode(param_value)
        
        # Strategy 2: Look in Referer header or URL for context
        referer_context = self._extract_button_from_referer(request_str)
        if referer_context:
            return referer_context
        
        # Strategy 3: Analyze the response (for GET requests or redirects)
        if response_bytes:
            response_button = self._extract_button_from_response(response_bytes)
            if response_button:
                return response_button
        
        # Strategy 4: Look for onclick or other JavaScript events
        js_button = self._extract_button_from_javascript(request_str)
        if js_button:
            return js_button
        
        # Strategy 5: URL-based extraction (last resort)
        url_button = self._extract_button_from_url(request_str)
        if url_button:
            return url_button
        
        # If nothing found, return empty string
        return u""

    def _extract_button_from_referer(self, request_str):
        """Extract button context from Referer header or URL patterns"""
        # Look for Referer header
        referer_match = re.search(r'Referer:\s*([^\r\n]+)', request_str, re.IGNORECASE)
        if referer_match:
            referer_url = referer_match.group(1)
            # Extract last meaningful path segment
            path_parts = referer_url.split('/')
            for part in reversed(path_parts):
                if part and not part.startswith('http') and '=' not in part and '?' not in part:
                    # Decode URL-encoded characters
                    try:
                        import urllib
                        decoded = urllib.unquote(part)
                        if decoded and len(decoded) < 30:
                            return self._safe_unicode(decoded)
                    except:
                        pass
        
        return None

    def _extract_button_from_response(self, response_bytes, request_url=None):
        """Extract button name from HTML response"""
        if not response_bytes:
            return None
        
        # Try the simple method first
        if request_url:
            button_name = self._extract_button_simple(response_bytes, request_url)
            if button_name:
                return button_name
        
        # Fallback to navigation extraction
        try:
            response_str = response_bytes.tostring() if hasattr(response_bytes, 'tostring') else str(response_bytes)
            return self._extract_from_navigation(response_str)
        except:
            return None

    def _extract_from_navigation(self, html_content):
        """Extract button text from navigation menus"""
        import re
        
        # Common navigation menu patterns
        nav_patterns = [
            (r'<nav[^>]*>(.*?)</nav>', 'nav'),
            (r'<ul[^>]*class=["\'][^"\']*nav[^"\']*["\'][^>]*>(.*?)</ul>', 'ul-nav'),
            (r'<div[^>]*class=["\'][^"\']*menu[^"\']*["\'][^>]*>(.*?)</div>', 'div-menu'),
            (r'<ul[^>]*class=["\'][^"\']*category[^"\']*["\'][^>]*>(.*?)</ul>', 'ul-category'),
            (r'<ul[^>]*class=["\'][^"\']*list[^"\']*["\'][^>]*>(.*?)</ul>', 'ul-list'),
        ]
        
        for pattern, pattern_type in nav_patterns:
            nav_matches = re.findall(pattern, html_content, re.IGNORECASE | re.DOTALL)
            if nav_matches:
                # Take the first (likely main) navigation
                nav_html = nav_matches[0]
                
                # Extract all links from this navigation
                links = self._extract_links_from_html(nav_html)
                
                if links:
                    # Return the text of the first meaningful link
                    for href, text in links:
                        text = text.strip()
                        if text and len(text) > 1 and len(text) < 50:
                            decoded = self._decode_html_entities(text)
                            if decoded and decoded.strip():
                                return decoded.strip()
        
        return None

    def _extract_links_from_html(self, html_content):
        """Extract all href/text pairs from HTML content"""
        import re
        
        links = []
        anchor_pattern = r'<a\s+[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
        
        matches = re.findall(anchor_pattern, html_content, re.IGNORECASE | re.DOTALL)
        
        for href, text in matches:
            # Clean the text
            text = text.strip()
            text = re.sub(r'<[^>]+>', '', text)
            text = re.sub(r'\s+', ' ', text)
            
            # Skip empty or very long text
            if text and len(text) < 100:
                links.append((href, text))
        
        return links

    def _extract_button_from_javascript(self, request_str):
        """Look for button names in JavaScript onclick handlers"""
        # Look for onclick handlers with meaningful text
        onclick_patterns = [
            r'onclick\s*=\s*["\'][^"\']*["\']\s*>([^<]{1,30})<',
            r'onclick\s*:\s*["\'][^"\']*["\']\s*,\s*["\']([^"\']{1,30})["\']',
        ]
        
        import re
        for pattern in onclick_patterns:
            matches = re.findall(pattern, request_str, re.IGNORECASE)
            if matches:
                text = matches[0].strip()
                if text:
                    return self._safe_unicode(text)
        
        return None

    def _extract_button_from_url(self, request_str):
        """Extract button context from URL path"""
        # Look for URL in request
        url_match = re.search(r'(?:GET|POST|PUT|DELETE|PATCH)\s+([^\s]+)', request_str)
        if url_match:
            url = url_match.group(1)
            # Extract last non-empty path segment
            path_parts = url.split('/')
            for part in reversed(path_parts):
                if part and '?' not in part and '=' not in part and len(part) < 20:
                    # Clean up common file extensions
                    if '.' in part:
                        part = part.split('.')[0]
                    if part and not part.isdigit():
                        return self._safe_unicode(part.replace('-', ' ').replace('_', ' '))
        
        return None
    
    def _extract_button_simple(self, response_bytes, request_url):
        """Simple but effective button extraction"""
        if not response_bytes or not request_url:
            return None
        
        try:
            response_str = response_bytes.tostring() if hasattr(response_bytes, 'tostring') else str(response_bytes)
        except:
            return None
        
        import re
        
        # Extract the last part of the request URL (for matching)
        url_parts = request_url.split('/')
        last_part = url_parts[-1] if url_parts else ''
        
        # Look for ALL anchor tags in the response
        anchor_pattern = r'<a\s+[^>]*href\s*=\s*["\'][^"\']*["\'][^>]*>([^<]+)</a>'
        all_anchors = re.findall(anchor_pattern, response_str, re.IGNORECASE | re.DOTALL)
        
        # Also look for anchor tags with href attribute
        href_pattern = r'<a\s+[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
        href_anchors = re.findall(href_pattern, response_str, re.IGNORECASE | re.DOTALL)
        
        # Try to match by URL path first
        for href, text in href_anchors:
            if href and (href in request_url or request_url.endswith(href)):
                text = text.strip()
                text = re.sub(r'<[^>]+>', '', text)
                text = re.sub(r'\s+', ' ', text)
                if text:
                    decoded = self._decode_html_entities(text)
                    if decoded:
                        return decoded
        
        # If no match, return the first meaningful anchor text
        for text in all_anchors:
            text = text.strip()
            text = re.sub(r'<[^>]+>', '', text)
            text = re.sub(r'\s+', ' ', text)
            
            # Skip if it looks like a URL or file
            if (len(text) < 2 or len(text) > 50 or 
                text.startswith('http') or 
                '.' in text and any(ext in text.lower() for ext in ['.jpg', '.png', '.gif', '.js', '.css', '.html'])):
                continue
            
            if text:
                decoded = self._decode_html_entities(text)
                if decoded:
                    return decoded
        
        return None


    def _safe_unicode(self, text):
        """Safely convert to Unicode string"""
        if text is None:
            return u""
        try:
            if isinstance(text, unicode):
                return text
            elif isinstance(text, str):
                return text.decode('utf-8', 'ignore')
            else:
                return unicode(str(text), 'utf-8', 'ignore')
        except:
            return u""

    def _decode_html_entities(self, text):
        """Decode HTML entities to proper characters"""
        if not text:
            return u""
        
        try:
            # First handle numeric entities (&#1234; or &#x4e2d;)
            import re
            
            def decode_numeric(match):
                entity = match.group(1)
                try:
                    if entity.startswith('#x'):
                        # Hex entity
                        return unichr(int(entity[2:], 16))
                    elif entity.startswith('#'):
                        # Decimal entity
                        return unichr(int(entity[1:]))
                    else:
                        return match.group(0)
                except:
                    return match.group(0)
            
            # Decode numeric entities
            text = re.sub(r'&(#(?:x[0-9a-fA-F]+|[0-9]+));', decode_numeric, text)
            
            # Handle common named entities
            html_entities = {
                'nbsp': ' ', 'lt': '<', 'gt': '>', 'amp': '&',
                'quot': '"', 'apos': "'", 'cent': '¢', 'pound': '£',
                'yen': '¥', 'euro': '€', 'copy': '©', 'reg': '®'
            }
            
            def decode_named(match):
                entity = match.group(1)
                if entity in html_entities:
                    return html_entities[entity]
                return match.group(0)
            
            text = re.sub(r'&([a-zA-Z]+);', decode_named, text)
            
            return text
        except:
            return text
    

    def _try_extract_button_manual(self):
        """Manual button extraction for selected rows"""
        selected_rows = [self.log_table.convertRowIndexToModel(i) 
                        for i in self.log_table.getSelectedRows()]
        if not selected_rows:
            JOptionPane.showMessageDialog(None,
                "Please select one or more rows first",
                "No Selection",
                JOptionPane.WARNING_MESSAGE)
            return
        
        extracted_count = 0
        for row in selected_rows:
            if row < len(self._display_to_request_map):
                actual_index = self._display_to_request_map[row]
                if actual_index < len(self.requests):
                    req = self.requests[actual_index]
                    message_info = req['messageInfo']
                    
                    # Try extraction with request URL
                    response_bytes = message_info.getResponse()
                    request_url = req.get('request_url', '')
                    if response_bytes and request_url:
                        button_name = self._extract_button_from_response(response_bytes, request_url)
                        
                        if button_name:
                            # Update the table
                            self.log_model.setValueAt(button_name, row, 3)  # Button Name column
                            # Update request data
                            req['button_name'] = button_name
                            extracted_count += 1
        
        # Show results
        if extracted_count > 0:
            JOptionPane.showMessageDialog(None,
                "Extracted button names for {} of {} selected requests".format(
                    extracted_count, len(selected_rows)),
                "Extraction Results",
                JOptionPane.INFORMATION_MESSAGE)
        else:
            JOptionPane.showMessageDialog(None,
                "Could not extract button names from selected requests",
                "No Button Found",
                JOptionPane.WARNING_MESSAGE)

    def _extract_from_navigation_menu(self, response_bytes, current_url):
        """Extract button name from navigation menu based on current URL"""
        if not response_bytes:
            return None
        
        try:
            response_str = response_bytes.tostring() if hasattr(response_bytes, 'tostring') else str(response_bytes)
        except:
            return None
        
        import re
        import urllib
        
        # Extract path from current URL
        current_path = None
        if current_url:
            try:
                # Parse URL to get path
                from java.net import URL
                url_obj = URL(current_url)
                current_path = url_obj.getPath()
            except:
                # Fallback: extract path manually
                path_match = re.search(r'https?://[^/]+(/[^?#]*)', current_url)
                if path_match:
                    current_path = path_match.group(1)
        
        if not current_path:
            return None
        
        # Look for navigation menus (common patterns)
        nav_patterns = [
            r'<nav[^>]*>(.*?)</nav>',
            r'<ul[^>]*class=["\'][^"\']*nav[^"\']*["\'][^>]*>(.*?)</ul>',
            r'<div[^>]*class=["\'][^"\']*menu[^"\']*["\'][^>]*>(.*?)</div>',
        ]
        
        for pattern in nav_patterns:
            nav_matches = re.findall(pattern, response_str, re.IGNORECASE | re.DOTALL)
            for nav_content in nav_matches:
                # Look for anchor tags within navigation
                anchor_pattern = r'<a\s+[^>]*href\s*=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
                anchors = re.findall(anchor_pattern, nav_content, re.IGNORECASE | re.DOTALL)
                
                for href, text in anchors:
                    # Decode URL for comparison
                    try:
                        decoded_href = urllib.unquote(href)
                    except:
                        decoded_href = href
                    
                    # Check if this link matches the current path
                    if decoded_href == current_path or current_path.endswith(decoded_href):
                        # Clean and return the text
                        text = text.strip()
                        text = re.sub(r'<[^>]+>', '', text)
                        text = re.sub(r'\s+', ' ', text)
                        if text:
                            return self._decode_html_entities(text)
        
        return None


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
                # Ensure directory path starts with /
                if not dir_path.startswith('/'):
                    dir_path = '/' + dir_path
                # Don't force trailing slash - let users specify exactly what they want
                self._include_directories.append(dir_path)

        # Process exclude directories
        self._exclude_directories = []
        if exclude_dir_text:
            directories = [dir_path.strip() for dir_path in exclude_dir_text.split(",") if dir_path.strip()]
            for dir_path in directories:
                # Ensure directory path starts with /
                if not dir_path.startswith('/'):
                    dir_path = '/' + dir_path
                # Don't force trailing slash - let users specify exactly what they want
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
                # Remove trailing slash for comparison if present
                clean_dir_path = dir_path.rstrip('/')
                # Check if the URL path contains the directory path (not just starts with)
                if clean_dir_path in url_path:
                    has_include_dir = True
                    break
            if not has_include_dir:
                return False

        # Check exclude directories (if any are specified)
        if self._exclude_directories:
            for dir_path in self._exclude_directories:
                # Remove trailing slash for comparison if present
                clean_dir_path = dir_path.rstrip('/')
                # Check if the URL path contains the directory path (not just starts with)
                if clean_dir_path in url_path:
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
        return "Metsuke"

