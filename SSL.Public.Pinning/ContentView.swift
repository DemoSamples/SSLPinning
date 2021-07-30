//
//  ContentView.swift
//  SSL.Public.Pinning
//
//  Created by user on 30/07/2021.
//

import SwiftUI

struct ContentView: View {
    var body: some View {
        Button("Call API") {
            NetworkManager(option: .publicKey).apiCall()
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
