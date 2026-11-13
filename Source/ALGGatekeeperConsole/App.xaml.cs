using ALGGatekeeper.Contracts;
using System.Windows;
using System.Windows.Threading;

namespace ALGGatekeeperConsole
{
    public partial class App : Application
    {
        public App()
        {
            DispatcherUnhandledException += OnUnhandledException;
        }

        /// <summary>
        /// an unexpected error must not silently close the console
        /// </summary>
        private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            MessageBox.Show($"Unexpected error: {e.Exception.Message}", ProductInfo.DisplayName, MessageBoxButton.OK, MessageBoxImage.Error);
            e.Handled = true;
        }
    }
}
