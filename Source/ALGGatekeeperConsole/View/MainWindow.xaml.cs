using ALGGatekeeperConsole.ViewModel;
using System;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace ALGGatekeeperConsole.View
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void ConsoleTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (AutoscrollCheckBox.IsChecked == true)
                ConsoleTextbox.ScrollToEnd();
        }

        /// <summary>
        /// Ctrl+C copies the selected entries of a list
        /// </summary>
        private void ListViewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.C && Keyboard.Modifiers == ModifierKeys.Control && sender is ListView list)
            {
                var b = new StringBuilder();
                foreach (var listItem in list.SelectedItems)
                    b.AppendLine(listItem.ToString());

                if (b.Length > 0)
                    Clipboard.SetText(b.ToString());
            }
        }

        private void Window_Closed(object sender, EventArgs e)
        {
            (DataContext as IDisposable)?.Dispose();
        }
    }
}
