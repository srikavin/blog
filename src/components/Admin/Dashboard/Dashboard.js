import React, {Fragment} from 'react';
import {NavLink, Redirect, Route, Switch} from 'react-router-dom';
import styles from './Dashboard.module.css'
import {Button, ButtonGroup} from '@blueprintjs/core';
import PostManager from './PostManager/PostManager';
import TagManager from './TagManager/TagManager';
import RequireAuth from '../Auth/RequireAuth/RequireAuth';

class Dashboard extends React.Component {
    constructor(props) {
        super(props);
        console.log(props);
    }

    render() {
        return (
            <Fragment>
                <RequireAuth from={'/admin/'}/>
                <div className={styles.container}>
                    <div className={styles.header}>
                        <h1 className={styles.headerText}>
                            Dashboard
                        </h1>
                        <div className={styles.navigation}>
                            <ButtonGroup minimal={true}>
                                <NavLink activeClassName={styles.active} to={`${this.props.match.url}/posts`}>
                                    <Button>
                                        <div className={styles.navHeader}>Posts</div>
                                    </Button>
                                </NavLink>
                                <NavLink activeClassName={styles.active} to={`${this.props.match.url}/tags`}>
                                    <Button>
                                        <div className={styles.navHeader}>Tags</div>
                                    </Button>
                                </NavLink>
                            </ButtonGroup>
                        </div>
                    </div>
                    <div>
                        <Switch>
                            <Route path={`${this.props.match.url}/posts`} component={this.passProps(PostManager)}/>
                            <Route path={`${this.props.match.url}/tags`} component={this.passProps(TagManager)}/>
                            <Route render={() => <Redirect to={`${this.props.match.url}/posts`}/>}/>
                        </Switch>
                    </div>
                </div>
            </Fragment>
        )
    }

    passProps(Component) {
        return (props) => {
            return <Component containerClassName={styles.navigation} {...props}/>
        }
    }
}

Dashboard.propTypes = {};

export default Dashboard;