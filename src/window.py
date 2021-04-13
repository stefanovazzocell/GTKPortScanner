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
    treeview = Gtk.Template.Child()
    check_filter_open = Gtk.Template.Child()
    spinbutton_min = Gtk.Template.Child()
    spinbutton_max = Gtk.Template.Child()
    check_fast_scan = Gtk.Template.Child()
    progressbar = Gtk.Template.Child()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Add ListStore + Filter
        self.liststore = Gtk.ListStore(str, str, str)
        self.filter = self.liststore.filter_new()
        self.filter.set_visible_func(self.filter_fn)
        self.treeview.set_model(self.filter)
        self.treeview.set_enable_search(True)
        port_text = Gtk.TreeViewColumn("Port", Gtk.CellRendererText(), text=0)
        self.treeview.append_column(port_text)
        status_text = Gtk.TreeViewColumn("Status", Gtk.CellRendererText(), text=1)
        self.treeview.append_column(status_text)
        message = Gtk.TreeViewColumn("Message", Gtk.CellRendererText(), text=2)
        self.treeview.append_column(message)
        self.treeview.set_search_column(0)


    def ctrl_active(self, toggle):
        if toggle:
            self.btn_scan.set_sensitive(toggle)
            self.btn_scan.set_label("_Scan")
            self.btn_scan.set_tooltip_text("Start scanning")
        else:
            self.btn_scan.set_label("_Abort")
            self.btn_scan.set_tooltip_text("Request Abort")
        self.target_input.set_editable(toggle)
        self.spinbutton_min.set_editable(toggle)
        self.spinbutton_max.set_editable(toggle)
        self.check_fast_scan.set_sensitive(toggle)


    @Gtk.Template.Callback('toggle_filter')
    def toggle_filter(self, widget):
        self.filter.refilter()


    @Gtk.Template.Callback('run_scan')
    def run_scan(self, widget):
        if self.scanning:
            # Abort
            self.btn_scan.set_sensitive(False)
            self.progressbar.set_text("Aborting...")
            self.aborting = True
            return
        target     = self.target_input.get_text()
        port_start = self.spinbutton_min.get_value_as_int()
        port_end   = self.spinbutton_max.get_value_as_int()
        fast_scan  = self.check_fast_scan.get_active()
        if (port_start > port_end):
            self.progressbar.set_text("The start port cannot be greater than the end port</b>")
            return
        ui_timer = 0.1
        live_update = True
        delta = port_end - port_start + 1
        if delta >= 1000:
            ui_timer = 0.3
        if delta >= 8000:
            ui_timer = 1
        if delta >= 12000:
            ui_timer = 1
            live_update = False
        if delta >= 20000:
            ui_timer = 2
            live_update = False
        results = {}
        self.scanning = True
        self.aborting = False
        self.ctrl_active(False)
        self.liststore.clear()
        self.progressbar.set_text("Scanning...")
        self.progressbar.set_fraction(0)
        target_ip = target
        try:
            target_ip = gethostbyname(target_ip)
        except:
            self.progressbar.set_text(f'Error resolving IP for {target}')
        print(f'Resolved target to "{target_ip}"')
        done_queue, workers_count, todo_queue, workers = scan_init(target_ip, port_start, port_end, fast_scan)
        self.liststore.clear()
        for port in range(port_start, port_end + 1):
            self.liststore.append([str(port), "Scanning", ""])
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
                i = str(port)
                if not port in results:
                    active += 1
            # Aborting part 2
            if self.aborting:
                active = 0
            i = port_start
            if active == 0 or live_update:
                for row in self.liststore:
                    if i in results:
                        row[2] = results[i][1]
                        if results[i][0] == True:
                            row[1] = "Open"
                        else:
                            row[1] = "Closed"
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
        GLib.timeout_add(ui_timer*1000, callback, port_start, port_end)


    @Gtk.Template.Callback('update_scan')
    def update_scan(self, widget):
        self.scan_label.set_text(f'Scan {self.target_input.get_text()}')

    def filter_fn(self, model, iter, data):
        if self.check_filter_open.get_active():
            return (model[iter][1] == "Open")
        else:
            return True
