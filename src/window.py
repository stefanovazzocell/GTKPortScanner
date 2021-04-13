# window.py
#
# Copyright 2021 Stefano Vazzoler
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from gi.repository import Gtk, GLib
from time import sleep
from socket import gethostbyname
from .scanner import scan_init

@Gtk.Template(resource_path='/com/stefanovazzoler/portscanner/window.ui')
class PortscannerWindow(Gtk.ApplicationWindow):
    __gtype_name__ = 'PortscannerWindow'

    scanning = False
    aborting = False

    btn_scan = Gtk.Template.Child()
    scan_label = Gtk.Template.Child()
    target_input = Gtk.Template.Child()
    tcp_treeview = Gtk.Template.Child()
    udp_treeview = Gtk.Template.Child()
    check_filter_open = Gtk.Template.Child()
    check_active_probing = Gtk.Template.Child()
    spinbutton_min = Gtk.Template.Child()
    spinbutton_max = Gtk.Template.Child()
    check_fast_scan = Gtk.Template.Child()
    progressbar = Gtk.Template.Child()
    warning_window = Gtk.Template.Child()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Add ListStore + Filter
        self.tcp_liststore = Gtk.ListStore(int, str, str, str)
        self.tcp_filter = self.tcp_liststore.filter_new()
        self.tcp_filter.set_visible_func(self.filter_fn)
        self.tcp_treeview.set_model(self.tcp_filter)
        self.tcp_treeview.set_enable_search(True)
        port_text = Gtk.TreeViewColumn("Port", Gtk.CellRendererText(), text=0)
        self.tcp_treeview.append_column(port_text)
        status = Gtk.TreeViewColumn("Status", Gtk.CellRendererText(), text=1)
        self.tcp_treeview.append_column(status)
        services = Gtk.TreeViewColumn("Services", Gtk.CellRendererText(), text=2)
        self.tcp_treeview.append_column(services)
        message = Gtk.TreeViewColumn("Message", Gtk.CellRendererText(), text=3)
        self.tcp_treeview.append_column(message)
        self.tcp_treeview.set_search_column(0)

        self.udp_liststore = Gtk.ListStore(int, str, str, str)
        self.udp_filter = self.udp_liststore.filter_new()
        self.udp_filter.set_visible_func(self.filter_fn)
        self.udp_treeview.set_model(self.udp_filter)
        self.udp_treeview.set_enable_search(True)
        port_text = Gtk.TreeViewColumn("Port", Gtk.CellRendererText(), text=0)
        self.udp_treeview.append_column(port_text)
        status = Gtk.TreeViewColumn("Status", Gtk.CellRendererText(), text=1)
        self.udp_treeview.append_column(status)
        services = Gtk.TreeViewColumn("Services", Gtk.CellRendererText(), text=2)
        self.udp_treeview.append_column(services)
        message = Gtk.TreeViewColumn("Message", Gtk.CellRendererText(), text=3)
        self.udp_treeview.append_column(message)
        self.udp_treeview.set_search_column(0)


    def ctrl_active(self, toggle):
        if toggle:
            self.btn_scan.set_sensitive(toggle)
            self.btn_scan.set_label("_Scan")
            self.btn_scan.set_tooltip_text("Start scanning")
        else:
            self.btn_scan.set_label("_Abort")
            self.btn_scan.set_tooltip_text("Request Abort")
        self.target_input.set_editable(toggle)
        self.target_input.set_sensitive(toggle)
        self.spinbutton_min.set_editable(toggle)
        self.spinbutton_min.set_sensitive(toggle)
        self.spinbutton_max.set_editable(toggle)
        self.spinbutton_max.set_sensitive(toggle)
        self.check_fast_scan.set_sensitive(toggle)
        self.check_active_probing.set_sensitive(toggle)


    @Gtk.Template.Callback('toggle_filter')
    def toggle_filter(self, widget):
        self.tcp_filter.refilter()
        self.udp_filter.refilter()


    @Gtk.Template.Callback('update_scan')
    def update_scan(self, widget):
        self.scan_label.set_text(f'Scan {self.target_input.get_text()}')

    def filter_fn(self, model, iter, data):
        if self.check_filter_open.get_active():
            return model[iter][1] == "Open"
        else:
            return True


    def scan(self):
        target         = self.target_input.get_text()
        port_start     = self.spinbutton_min.get_value_as_int()
        port_end       = self.spinbutton_max.get_value_as_int()
        fast_scan      = self.check_fast_scan.get_active()
        active_probing = self.check_active_probing.get_active()
        ui_timer = 120
        live_update = True
        delta = port_end - port_start + 1
        if delta >= 1000:
            ui_timer = 320
        if delta >= 5000:
            ui_timer = 1200
        if delta >= 9000:
            ui_timer = 1200
            live_update = False
        if delta >= 20000:
            ui_timer = 3200
            live_update = False
        results = {}
        self.scanning = True
        self.aborting = False
        self.ctrl_active(False)
        self.tcp_liststore.clear()
        self.progressbar.set_text("Scanning...")
        self.progressbar.set_fraction(0)
        target_ip = target
        try:
            target_ip = gethostbyname(target_ip)
        except:
            self.progressbar.set_text(f'Error resolving IP for {target}')
        print(f'Resolved target to "{target_ip}"')
        done_queue, workers_count, todo_queue, workers = scan_init(target_ip, port_start, port_end, fast_scan, active_probing)
        self.tcp_liststore.clear()
        self.udp_liststore.clear()
        for port in range(port_start, port_end + 1):
            self.tcp_liststore.append([port, "Scanning", "", ""])
            self.udp_liststore.append([port, "Scanning", "", ""])

        def callback(*args):
            # If abort clear queue
            if self.aborting:
                try:
                    while True:
                        todo_queue.get(block=True, timeout=0.01)
                except:
                    pass
                for proc in workers:
                    try:
                        proc.join()
                    except:
                        pass
            # Pull down new results
            new_data = []
            while True:
                try:
                    new_data.append(done_queue.get(block=True, timeout=0.003))
                except:
                    break
            for d in new_data:
                results[d[0]] = d[1]
            # Process data
            port_start = args[0]
            port_end   = args[1]
            total      = port_end - port_start + 1
            active     = 0
            for port in range(port_start, port_end + 1):
                if not port in results:
                    active += 1
            # Aborting part 2
            if self.aborting:
                active = 0
            if active == 0 or live_update:
                i = port_start
                for row in self.tcp_liststore:
                    if i in results:
                        row[1] = results[i].tcp_status()
                        row[2] = results[i].tcp_info()
                        row[3] = results[i].tcp_msg
                    i += 1
                i = port_start
                for row in self.udp_liststore:
                    if i in results:
                        row[1] = results[i].udp_status()
                        row[2] = results[i].udp_info()
                        row[3] = results[i].udp_msg
                    i += 1
            self.progressbar.set_fraction((total - active)/total)
            if active == 0:
                self.progressbar.set_text('Ready')
                self.scanning = False
                self.aborting = False
                self.ctrl_active(True)
                return False
            self.progressbar.set_fraction((total - active)/total)
            self.progressbar.set_text(f'Scanned {(total-active)} ports out of {total} ({workers_count} workers)')
            return True

        GLib.timeout_add(ui_timer, callback, port_start, port_end)


    @Gtk.Template.Callback('run_scan')
    def run_scan(self, widget):
        if self.scanning:
            # Abort
            self.btn_scan.set_sensitive(False)
            self.progressbar.set_text("Aborting...")
            self.aborting = True
            return
        port_start = self.spinbutton_min.get_value_as_int()
        port_end   = self.spinbutton_max.get_value_as_int()
        fast_scan  = self.check_fast_scan.get_active()
        if (port_start > port_end):
            self.progressbar.set_text("The start port cannot be greater than the end port</b>")
            return
        if (port_start + 8000) < port_end and fast_scan:
            self.btn_scan.set_sensitive(False)
            self.ctrl_active(False)
            self.warning_window.set_visible(True)
        else:
            self.scan()

    @Gtk.Template.Callback('cancel_btn')
    def cancel_btn(self, widget):
        self.warning_window.set_visible(False)
        self.ctrl_active(True)

    @Gtk.Template.Callback('continue_btn')
    def continue_btn(self, widget):
        self.warning_window.set_visible(False)
        self.btn_scan.set_sensitive(True)
        self.scan()
