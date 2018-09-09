import React from 'react';
import {Route, Switch} from 'react-router-dom'
import DocumentTitle from 'react-document-title';

import './App.module.css';
import {DynamicLoading} from './components/DynamicLoading/DynamicLoading';
import Loadable from 'react-loadable';
import Landing from './components/Landing/Landing'
import Navigation from './components/Navigation/Navigation';
import Post from './components/Post/Post';
import Home from './components/Home/Home';

const Auth = Loadable({
    loader: () => import(/* webpackChunkName: "auth" */'./components/Admin/Auth/Auth'),
    loading: DynamicLoading
});

const Admin = Loadable({
    loader: () => import(/* webpackChunkName: "admin" */'./components/Admin/Admin'),
    loading: DynamicLoading
});

class App extends React.Component {
    render() {
        return (
            <div className="App">
                <DocumentTitle title="Blog"/>
                <header className="App-header">
                    <Navigation/>
                </header>
                <div className='AppContent'>
                    <Switch>
                        <Route exact path="/login" component={Auth}/>
                        <Route exact path="/" component={Landing}/>
                        <Route exact path="/blog" component={Home}/>
                        <Route exact path="/blog/posts/:slug" component={Post}/>
                        <Route path="/admin" component={Admin}/>
                    </Switch>
                </div>
            </div>
        );
    }
}

export default App;
