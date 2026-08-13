// Windows release builds must not pop a console window behind the panel.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    patchbay_app_lib::run()
}
