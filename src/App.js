import React from 'react';
import {Route, Switch} from 'react-router-dom'
import DocumentTitle from 'react-document-title';
import {hot} from 'react-hot-loader'

import './App.css';
import Navigation from './components/Navigation/Navigation';
import {DynamicLoading} from './components/DynamicLoading/DynamicLoading';
import Loadable from 'react-loadable';

const Auth = Loadable({
    loader: () => import('./components/Auth/Auth'),
    loading: DynamicLoading
});

const Post = Loadable({
    loader: () => import('./components/Post/Post'),
    loading: DynamicLoading
});

const PostEditor = Loadable({
    loader: () => import('./components/PostEditor/PostEditor'),
    loading: DynamicLoading
});

const Home = Loadable({
    loader: () => import('./components/Home/Home'),
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
                <Switch>
                    <Route path="/login" component={Auth}/>
                    <Route exact path="/" component={Home}/>
                    <Route exact path="/posts/:slug" component={Post}/>
                    <Route exact path="/edit/:id" component={PostEditor}/>
                </Switch>
            </div>
        );
    }
}

export default hot(module)(App);
