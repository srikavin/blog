import React from 'react';
import {Route, Switch} from 'react-router-dom'

import './App.css';
import 'normalize.css/normalize.css';
import {DynamicLoading} from './components/DynamicLoading/DynamicLoading';
import Loadable from 'react-loadable';
import Navigation from './components/Navigation/Navigation';
import Post from './components/Post/Post';
import Home from './components/Home/Home';
import NotFound from './components/NotFound';
import FilteredPostList from './components/PostPreviews/FilteredPostList/FilteredPostList';
import {Helmet} from "react-helmet";
import {ThemeContext} from "./components/Theme";
import cx from 'classnames'

const Auth = Loadable({
    loader: () => import(/* webpackChunkName: "auth" */'./components/Admin/Auth/Auth'),
    loading: DynamicLoading
});

const Admin = Loadable({
    loader: () => import(/* webpackChunkName: "admin" */'./components/Admin/Admin'),
    loading: DynamicLoading
});

class App extends React.Component {
    static contextType = ThemeContext

    render() {
        document.body.className = (cx(this.context))

        return (
            <div className={cx('App', this.context)}>
                <Helmet>
                    <title>Blog</title>
                </Helmet>
                <header className="App-header">
                    <Navigation/>
                </header>
                <div className='AppContent'>
                    <Switch>
                        <Route exact path="/login" component={Auth}/>
                        <Route exact path="/" component={Home}/>
                        <Route exact path="/posts/:slug" component={Post}/>
                        <Route exact path="/tag/:tags" component={FilteredPostList}/>
                        <Route exact path="/tag/" component={FilteredPostList}/>
                        <Route path="/admin" component={Admin}/>
                        <Route path="/404" component={NotFound}/>
                        <Route component={NotFound}/>
                    </Switch>
                </div>
            </div>
        );
    }
}

export default App;
