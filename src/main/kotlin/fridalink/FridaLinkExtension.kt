package fridalink

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import fridalink.service.FridaLinkController
import fridalink.ui.FridaLinkTab

class FridaLinkExtension : BurpExtension {
    override fun initialize(montoyaApi: MontoyaApi) {
        montoyaApi.extension().setName("FridaLink")

        val controller = FridaLinkController(montoyaApi)
        val tab = FridaLinkTab(controller, montoyaApi.logging())

        montoyaApi.userInterface().registerSuiteTab("FridaLink", tab.root)
        controller.start()
    }
}
