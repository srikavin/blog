import React from 'react';
import {Route, Switch} from 'react-router-dom'
import './data/store'
import './App.css';

import Auth from './components/Auth/Auth';
import Home from './components/Home/Home';
import Navigation from "./components/Navigation/Navigation";
import Post from "./components/Post/Post";

class App extends React.Component {
    constructor(props) {
        super(props);
    }

    render() {
        return (
            <div className="App">
                <header className="App-header">
                    <Navigation/>
                </header>
                <Switch>
                    <Route path="/login" component={Auth}/>
                    <Route exact path="/" component={Home}/>
                    <Route exact path="/posts/:id" component={Post}/>
                </Switch>
            </div>
        );
    }
}

export default App;
