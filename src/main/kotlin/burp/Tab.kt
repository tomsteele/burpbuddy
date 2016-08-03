package burp

import java.awt.Component

class Tab(val name: String): ITab {
    override fun getTabCaption(): String {
        return name
    }

    override fun getUiComponent(): Component {
        throw UnsupportedOperationException("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}