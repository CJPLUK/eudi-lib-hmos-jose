package ohos_app_cangjie_entry

import kit.ArkUI.*
import ohos.arkui.state_macro_manage.Entry
import ohos.arkui.state_macro_manage.Component
import ohos.arkui.state_macro_manage.State

import ohos_app_cangjie_eudi_cjjose.runJoseDemo

@Entry
@Component
class EntryView {
    @State
    var resultText: String = "Press the button to run JOSE demo"

    func build() {
        Column {
            Button("Run JOSE Demo")
                .onClick({
                    evt => this.resultText = runJoseDemo()
                })
                .fontSize(18)
                .width(80.percent)
                .height(50.vp)
                .margin(top: 40.vp)
            Text(this.resultText)
                .fontSize(14)
                .width(90.percent)
                .margin(top: 24.vp)
        }
        .width(100.percent)
        .height(100.percent)
        .justifyContent(FlexAlign.Start)
        .padding(top: 80.vp)
    }
}
