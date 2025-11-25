from PySide6.QtGui import QColor, QPalette, QFont
from PySide6.QtWidgets import QApplication


class StyleManager:
    """Manages application styles and themes."""
    
    # Color schemes
    DARK_THEME = {
        "background": QColor(40, 44, 52),
        "surface": QColor(33, 37, 43),
        "primary": QColor(61, 174, 233),
        "secondary": QColor(142, 68, 173),
        "accent": QColor(26, 188, 156),
        "error": QColor(231, 76, 60),
        "warning": QColor(241, 196, 15),
        "success": QColor(46, 204, 113),
        "text": QColor(255, 255, 255),
        "text_secondary": QColor(189, 195, 199),
        "disabled": QColor(127, 140, 141)
    }
    
    LIGHT_THEME = {
        "background": QColor(240, 240, 240),
        "surface": QColor(255, 255, 255),
        "primary": QColor(41, 128, 185),
        "secondary": QColor(142, 68, 173),
        "accent": QColor(26, 188, 156),
        "error": QColor(231, 76, 60),
        "warning": QColor(243, 156, 18),
        "success": QColor(39, 174, 96),
        "text": QColor(44, 62, 80),
        "text_secondary": QColor(127, 140, 141),
        "disabled": QColor(189, 195, 199)
    }
    
    @staticmethod
    def apply_theme(theme_name: str):
        """Apply the selected theme to the application.
        
        Args:
            theme_name: The name of the theme to apply ("dark" or "light")
        """
        theme_name = theme_name.lower()
        
        if theme_name == "dark":
            StyleManager._apply_dark_theme()
        elif theme_name == "light":
            StyleManager._apply_light_theme()
    
    @staticmethod
    def _apply_dark_theme():
        """Apply the dark theme to the application."""
        colors = StyleManager.DARK_THEME
        
        # Create dark palette
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, colors["background"])
        palette.setColor(QPalette.ColorRole.WindowText, colors["text"])
        palette.setColor(QPalette.ColorRole.Base, colors["surface"])
        palette.setColor(QPalette.ColorRole.AlternateBase, colors["background"])
        palette.setColor(QPalette.ColorRole.ToolTipBase, colors["surface"])
        palette.setColor(QPalette.ColorRole.ToolTipText, colors["text"])
        palette.setColor(QPalette.ColorRole.Text, colors["text"])
        palette.setColor(QPalette.ColorRole.Button, colors["background"])
        palette.setColor(QPalette.ColorRole.ButtonText, colors["text"])
        palette.setColor(QPalette.ColorRole.BrightText, colors["accent"])
        palette.setColor(QPalette.ColorRole.Link, colors["primary"])
        palette.setColor(QPalette.ColorRole.Highlight, colors["primary"])
        palette.setColor(QPalette.ColorRole.HighlightedText, colors["text"])
        
        # Disabled colors
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, colors["disabled"])
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, colors["disabled"])
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, colors["disabled"])
        
        # Ensure action buttons have visible text
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
        
        app = QApplication.instance()
        app.setPalette(palette)
        
        # Apply stylesheet for additional customization
        app.setStyleSheet("""
            QToolTip { 
                color: #ffffff; 
                background-color: #2a2a2a; 
                border: 1px solid #767676; 
                border-radius: 4px; 
                padding: 4px;
                opacity: 200; 
            }
            
            QWidget {
                background-color: #2c2c2c;
                color: #ffffff;
            }
            
            QTabWidget::pane {
                border: 1px solid #444;
                border-radius: 4px;
                padding: 2px;
            }
            
            QTabBar::tab {
                background-color: #3a3a3a;
                color: #b1b1b1;
                border: 1px solid #444;
                border-bottom-color: #444;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                padding: 6px 12px;
                margin-right: 2px;
            }
            
            QTabBar::tab:selected, QTabBar::tab:hover {
                background-color: #3daee9;
                color: #ffffff;
            }
            
            QTabBar::tab:selected {
                border-bottom-color: #3daee9;
            }
            
            QPushButton {
                background-color: #3a3a3a;
                color: #ffffff !important;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 5px 15px;
                min-width: 80px;
                font-weight: bold;
                text-align: center;
            }
            
            QPushButton:hover {
                background-color: #4a4a4a;
                border: 1px solid #666;
                color: #ffffff !important;
            }
            
            QPushButton:pressed {
                background-color: #2a2a2a;
                color: #ffffff !important;
            }
            
            QPushButton:disabled {
                background-color: #2a2a2a;
                color: #656565;
                border: 1px solid #3a3a3a;
            }
            
            QLineEdit, QTextEdit, QSpinBox, QDateTimeEdit, QComboBox {
                background-color: #232629;
                color: #eff0f1;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 4px;
            }
            
            QLineEdit:focus, QTextEdit:focus, QSpinBox:focus, QDateTimeEdit:focus, QComboBox:focus {
                border: 1px solid #3daee9;
            }
            
            QTableWidget {
                background-color: #232629;
                alternate-background-color: #2a2a2a;
                color: #eff0f1;
                gridline-color: #444;
                border: 1px solid #444;
                border-radius: 4px;
            }
            
            QTableWidget::item:selected {
                background-color: #3daee9;
                color: #ffffff;
            }
            
            QHeaderView::section {
                background-color: #3a3a3a;
                color: #eff0f1;
                padding: 5px;
                border: 1px solid #444;
            }
            
            QScrollBar:vertical {
                background-color: #232629;
                width: 14px;
                margin: 15px 0 15px 0;
                border: 1px solid #444;
                border-radius: 4px;
            }
            
            QScrollBar::handle:vertical {
                background-color: #3a3a3a;
                min-height: 30px;
                border-radius: 3px;
            }
            
            QScrollBar::handle:vertical:hover {
                background-color: #3daee9;
            }
            
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
            }
            
            QScrollBar:horizontal {
                background-color: #232629;
                height: 14px;
                margin: 0 15px 0 15px;
                border: 1px solid #444;
                border-radius: 4px;
            }
            
            QScrollBar::handle:horizontal {
                background-color: #3a3a3a;
                min-width: 30px;
                border-radius: 3px;
            }
            
            QScrollBar::handle:horizontal:hover {
                background-color: #3daee9;
            }
            
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                border: none;
                background: none;
            }
            
            QGroupBox {
                border: 1px solid #444;
                border-radius: 4px;
                margin-top: 20px;
                padding-top: 24px;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 5px;
                color: #eff0f1;
            }
            
            QMenuBar {
                background-color: #2c2c2c;
                color: #eff0f1;
            }
            
            QMenuBar::item {
                background: transparent;
                padding: 4px 10px;
            }
            
            QMenuBar::item:selected {
                background-color: #3daee9;
                color: #ffffff;
            }
            
            QMenu {
                background-color: #2c2c2c;
                color: #eff0f1;
                border: 1px solid #444;
            }
            
            QMenu::item {
                padding: 5px 30px 5px 20px;
            }
            
            QMenu::item:selected {
                background-color: #3daee9;
                color: #ffffff;
            }
            
            QMenu::separator {
                height: 1px;
                background-color: #444;
                margin: 4px 0;
            }
            
            QStatusBar {
                background-color: #2c2c2c;
                color: #eff0f1;
                border-top: 1px solid #444;
            }
        """)
    
    @staticmethod
    def _apply_light_theme():
        """Apply the light theme to the application."""
        colors = StyleManager.LIGHT_THEME
        
        # Create light palette
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, colors["background"])
        palette.setColor(QPalette.ColorRole.WindowText, colors["text"])
        palette.setColor(QPalette.ColorRole.Base, colors["surface"])
        palette.setColor(QPalette.ColorRole.AlternateBase, colors["background"])
        palette.setColor(QPalette.ColorRole.ToolTipBase, colors["surface"])
        palette.setColor(QPalette.ColorRole.ToolTipText, colors["text"])
        palette.setColor(QPalette.ColorRole.Text, colors["text"])
        palette.setColor(QPalette.ColorRole.Button, colors["background"])
        palette.setColor(QPalette.ColorRole.ButtonText, colors["text"])
        palette.setColor(QPalette.ColorRole.BrightText, colors["accent"])
        palette.setColor(QPalette.ColorRole.Link, colors["primary"])
        palette.setColor(QPalette.ColorRole.Highlight, colors["primary"])
        palette.setColor(QPalette.ColorRole.HighlightedText, colors["surface"])
        
        # Disabled colors
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, colors["disabled"])
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, colors["disabled"])
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, colors["disabled"])
        
        # Ensure action buttons have visible text
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(44, 62, 80))
        
        app = QApplication.instance()
        app.setPalette(palette)
        
        # Apply stylesheet for additional customization
        app.setStyleSheet("""
            QToolTip { 
                color: #31363b; 
                background-color: #f7f7f7; 
                border: 1px solid #c0c0c0; 
                border-radius: 4px; 
                padding: 4px;
                opacity: 200; 
            }
            
            QTabWidget::pane {
                border: 1px solid #c0c0c0;
                border-radius: 4px;
                padding: 2px;
            }
            
            QTabBar::tab {
                background-color: #e0e0e0;
                color: #31363b;
                border: 1px solid #c0c0c0;
                border-bottom-color: #c0c0c0;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                padding: 6px 12px;
                margin-right: 2px;
            }
            
            QTabBar::tab:selected, QTabBar::tab:hover {
                background-color: #2980b9;
                color: #ffffff;
            }
            
            QTabBar::tab:selected {
                border-bottom-color: #2980b9;
            }
            
            QPushButton {
                background-color: #e0e0e0;
                color: #31363b !important;
                border: 1px solid #c0c0c0;
                border-radius: 4px;
                padding: 5px 15px;
                min-width: 80px;
                font-weight: bold;
                text-align: center;
            }
            
            QPushButton:hover {
                background-color: #f0f0f0;
                border: 1px solid #a0a0a0;
                color: #31363b !important;
            }
            
            QPushButton:pressed {
                background-color: #d0d0d0;
                color: #31363b !important;
            }
            
            QPushButton:disabled {
                background-color: #f0f0f0;
                color: #a0a0a0;
                border: 1px solid #e0e0e0;
            }
            
            QLineEdit, QTextEdit, QSpinBox, QDateTimeEdit, QComboBox {
                background-color: #ffffff;
                color: #31363b;
                border: 1px solid #c0c0c0;
                border-radius: 4px;
                padding: 4px;
            }
            
            QLineEdit:focus, QTextEdit:focus, QSpinBox:focus, QDateTimeEdit:focus, QComboBox:focus {
                border: 1px solid #2980b9;
            }
            
            QTableWidget {
                background-color: #ffffff;
                alternate-background-color: #f7f7f7;
                color: #31363b;
                gridline-color: #c0c0c0;
                border: 1px solid #c0c0c0;
                border-radius: 4px;
            }
            
            QTableWidget::item:selected {
                background-color: #2980b9;
                color: #ffffff;
            }
            
            QHeaderView::section {
                background-color: #e0e0e0;
                color: #31363b;
                padding: 5px;
                border: 1px solid #c0c0c0;
            }
            
            QScrollBar:vertical {
                background-color: #f0f0f0;
                width: 14px;
                margin: 15px 0 15px 0;
                border: 1px solid #c0c0c0;
                border-radius: 4px;
            }
            
            QScrollBar::handle:vertical {
                background-color: #c0c0c0;
                min-height: 30px;
                border-radius: 3px;
            }
            
            QScrollBar::handle:vertical:hover {
                background-color: #2980b9;
            }
            
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
            }
            
            QScrollBar:horizontal {
                background-color: #f0f0f0;
                height: 14px;
                margin: 0 15px 0 15px;
                border: 1px solid #c0c0c0;
                border-radius: 4px;
            }
            
            QScrollBar::handle:horizontal {
                background-color: #c0c0c0;
                min-width: 30px;
                border-radius: 3px;
            }
            
            QScrollBar::handle:horizontal:hover {
                background-color: #2980b9;
            }
            
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                border: none;
                background: none;
            }
            
            QGroupBox {
                border: 1px solid #c0c0c0;
                border-radius: 4px;
                margin-top: 20px;
                padding-top: 24px;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 5px;
                color: #31363b;
            }
            
            QMenuBar {
                background-color: #f0f0f0;
                color: #31363b;
            }
            
            QMenuBar::item {
                background: transparent;
                padding: 4px 10px;
            }
            
            QMenuBar::item:selected {
                background-color: #2980b9;
                color: #ffffff;
            }
            
            QMenu {
                background-color: #f0f0f0;
                color: #31363b;
                border: 1px solid #c0c0c0;
            }
            
            QMenu::item {
                padding: 5px 30px 5px 20px;
            }
            
            QMenu::item:selected {
                background-color: #2980b9;
                color: #ffffff;
            }
            
            QMenu::separator {
                height: 1px;
                background-color: #c0c0c0;
                margin: 4px 0;
            }
            
            QStatusBar {
                background-color: #f0f0f0;
                color: #31363b;
                border-top: 1px solid #c0c0c0;
            }
        """)
    
    # Base button style used across all button types
    base_style = """
        QPushButton {
            font-family: 'Segoe UI', Arial, sans-serif;
            outline: none;
        }
    """
    
    @staticmethod
    def get_button_style(button_type="default"):
        """Get style for a specific button type.
        
        Args:
            button_type: The type of button ("default", "primary", "danger", "success")
            
        Returns:
            The stylesheet for the button
        """
        if button_type == "primary":
            return StyleManager.base_style + """
                QPushButton {
                    background-color: #2196F3;
                    color: #ffffff !important;
                    border: 2px solid #1976D2;
                    border-radius: 6px;
                    padding: 12px 24px;
                    font-weight: 600;
                    text-align: center;
                    min-width: 110px;
                    min-height: 44px;
                    font-size: 14px;
                    letter-spacing: 0.5px;
                }
                QPushButton:hover {
                    background-color: #42A5F5;
                    border: 2px solid #2196F3;
                    color: #ffffff !important;
                }
                QPushButton:pressed {
                    background-color: #1976D2;
                    border: 2px solid #0D47A1;
                    color: #ffffff !important;
                }
                QPushButton:disabled {
                    background-color: #BBDEFB;
                    color: #E3F2FD;
                    border: 2px solid #BBDEFB;
                }
            """
        elif button_type == "danger":
            return StyleManager.base_style + """
                QPushButton {
                    background-color: #F44336;
                    color: #ffffff !important;
                    border: 2px solid #D32F2F;
                    border-radius: 6px;
                    padding: 12px 24px;
                    font-weight: 600;
                    text-align: center;
                    min-width: 110px;
                    min-height: 44px;
                    font-size: 14px;
                    letter-spacing: 0.5px;
                }
                QPushButton:hover {
                    background-color: #EF5350;
                    border: 2px solid #F44336;
                    color: #ffffff !important;
                }
                QPushButton:pressed {
                    background-color: #D32F2F;
                    border: 2px solid #B71C1C;
                    color: #ffffff !important;
                }
                QPushButton:disabled {
                    background-color: #FFCDD2;
                    color: #FFEBEE;
                    border: 2px solid #FFCDD2;
                }
            """
        elif button_type == "success":
            return StyleManager.base_style + """
                QPushButton {
                    background-color: #4CAF50;
                    color: white;
                    border: 2px solid #388E3C;
                    border-radius: 6px;
                    padding: 12px 24px;
                    font-weight: 600;
                    text-align: center;
                    min-width: 110px;
                    min-height: 44px;
                    font-size: 14px;
                    letter-spacing: 0.5px;
                }
                QPushButton:hover {
                    background-color: #66BB6A;
                    border: 2px solid #4CAF50;
                }
                QPushButton:pressed {
                    background-color: #388E3C;
                    border: 2px solid #1B5E20;
                }
                QPushButton:disabled {
                    background-color: #C8E6C9;
                    color: #E8F5E9;
                    border: 2px solid #C8E6C9;
                }
            """
        else:  # default
            return StyleManager.base_style + """
                QPushButton {
                    background-color: #78909C;
                    color: #ffffff !important;
                    border: 2px solid #546E7A;
                    border-radius: 6px;
                    padding: 12px 24px;
                    font-weight: 600;
                    text-align: center;
                    min-width: 110px;
                    min-height: 44px;
                    font-size: 14px;
                    letter-spacing: 0.5px;
                }
                QPushButton:hover {
                    background-color: #90A4AE;
                    border: 2px solid #78909C;
                    color: #ffffff !important;
                }
                QPushButton:pressed {
                    background-color: #546E7A;
                    border: 2px solid #37474F;
                    color: #ffffff !important;
                }
                QPushButton:disabled {
                    background-color: #CFD8DC;
                    color: #90A4AE !important;
                    border: 2px solid #CFD8DC;
                }
            """
    
    @staticmethod
    def get_action_button_style(button_type="default"):
        """Get style for action buttons in the file table.
        
        Args:
            button_type: The type of button ("default", "primary", "danger", "success")
            
        Returns:
            The stylesheet for the action button
        """
        action_base_style = """
            QPushButton {
                color: #ffffff !important;
                font-weight: bold !important;
                text-align: center !important;
                font-family: "Segoe UI", Arial, sans-serif !important;
                outline: none;
            }
        """
        
        if button_type == "primary":
            return action_base_style + """
                QPushButton {
                    background-color: #2196F3;
                    border: 2px solid #1976D2;
                    border-radius: 6px;
                    padding: 8px 16px;
                    min-width: 90px;
                    min-height: 38px;
                    font-size: 14px;
                    letter-spacing: 0.5px;
                    qproperty-iconSize: 18px 18px;
                    margin: 4px;
                }
                QPushButton:hover {
                    background-color: #42A5F5;
                    border: 2px solid #2196F3;
                    color: #ffffff !important;
                }
                QPushButton:pressed {
                    background-color: #1976D2;
                    border: 2px solid #0D47A1;
                    color: #ffffff !important;
                }
                QPushButton:disabled {
                    background-color: #BBDEFB;
                    color: #90A4AE !important;
                    border: 2px solid #BBDEFB;
                }
            """
        elif button_type == "danger":
            return action_base_style + """
                QPushButton {
                    background-color: #F44336;
                    border: 2px solid #D32F2F;
                    border-radius: 6px;
                    padding: 8px 16px;
                    min-width: 90px;
                    min-height: 38px;
                    font-size: 14px;
                    letter-spacing: 0.5px;
                    qproperty-iconSize: 18px 18px;
                    margin: 4px;
                }
                QPushButton:hover {
                    background-color: #EF5350;
                    border: 2px solid #F44336;
                    color: #ffffff !important;
                }
                QPushButton:pressed {
                    background-color: #D32F2F;
                    border: 2px solid #B71C1C;
                    color: #ffffff !important;
                }
                QPushButton:disabled {
                    background-color: #FFCDD2;
                    color: #90A4AE !important;
                    border: 2px solid #FFCDD2;
                }
            """
        elif button_type == "success":
            return action_base_style + """
                QPushButton {
                    background-color: #4CAF50;
                    border: 2px solid #388E3C;
                    border-radius: 6px;
                    padding: 8px 16px;
                    min-width: 90px;
                    min-height: 38px;
                    font-size: 14px;
                    letter-spacing: 0.5px;
                    qproperty-iconSize: 18px 18px;
                    margin: 4px;
                }
                QPushButton:hover {
                    background-color: #66BB6A;
                    border: 2px solid #4CAF50;
                    color: #ffffff !important;
                }
                QPushButton:pressed {
                    background-color: #388E3C;
                    border: 2px solid #1B5E20;
                    color: #ffffff !important;
                }
                QPushButton:disabled {
                    background-color: #C8E6C9;
                    color: #90A4AE !important;
                    border: 2px solid #C8E6C9;
                }
            """
        else:  # default
            return action_base_style + """
                QPushButton {
                    background-color: #78909C;
                    border: 2px solid #546E7A;
                    border-radius: 6px;
                    padding: 8px 16px;
                    min-width: 90px;
                    min-height: 38px;
                    font-size: 14px;
                    letter-spacing: 0.5px;
                    qproperty-iconSize: 18px 18px;
                    margin: 4px;
                }
                QPushButton:hover {
                    background-color: #90A4AE;
                    border: 2px solid #78909C;
                    color: #ffffff !important;
                }
                QPushButton:pressed {
                    background-color: #546E7A;
                    border: 2px solid #37474F;
                    color: #ffffff !important;
                }
                QPushButton:disabled {
                    background-color: #CFD8DC;
                    color: #90A4AE !important;
                    border: 2px solid #CFD8DC;
                }
            """
    
    @staticmethod
    def get_dialog_style():
        """Get stylesheet for dialog windows."""
        return """
            QDialog {
                background-color: palette(window);
                border-radius: 8px;
            }
            QGroupBox {
                border: 1px solid palette(mid);
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 5px;
                background-color: palette(window);
            }
        """
    
    @staticmethod
    def get_form_style():
        """Get stylesheet for form elements."""
        return """
            QLineEdit, QTextEdit, QComboBox, QSpinBox, QDateTimeEdit {
                border: 1px solid palette(mid);
                border-radius: 4px;
                padding: 5px;
                background-color: palette(base);
                selection-background-color: palette(highlight);
                selection-color: palette(highlighted-text);
            }
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus, QDateTimeEdit:focus {
                border: 1px solid palette(highlight);
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
        """
    
    @staticmethod
    def get_form_container_style():
        """Get stylesheet for form containers."""
        return """
            QWidget {
                background-color: transparent;
                border-radius: 8px;
                padding: 10px;
            }
        """
    
    @staticmethod
    def get_table_style():
        """Get stylesheet for table widgets."""
        return """
            QTableWidget {
                border: 1px solid palette(mid);
                border-radius: 4px;
                gridline-color: palette(mid);
                selection-background-color: palette(highlight);
                selection-color: palette(highlighted-text);
            }
            QTableWidget::item {
                padding: 4px;
                border-bottom: 1px solid palette(mid);
            }
            QHeaderView::section {
                background-color: palette(button);
                padding: 4px;
                border: 1px solid palette(mid);
                font-weight: bold;
            }
        """
